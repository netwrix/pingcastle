#nullable enable

namespace PingCastleAutoUpdater.ConfigurationOrchestration;

using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using ConfigurationConversion;
using ConfigurationMerge;
using PingCastleCommon;

/// <summary>
/// Strategy implementation for actual (non-dry-run) configuration handling.
/// Performs real file operations and merges.
/// </summary>
public class RealConfigurationStrategy : ConfigurationStrategyBase
{
    public RealConfigurationStrategy(ConfigurationPathContext pathContext)
        : base(pathContext)
    {
    }

    public override void HandleXmlConfigDuringExtraction(ZipArchiveEntry entry, string targetFilePath)
    {
        // Copy into temp file ready to merge.
        string tempName = $"tempNew_{entry.FullName}";
        PerformCopy(entry, tempName);

        try
        {
            // Calculate full path name for temp file
            string sourceFilePath = FilesValidator.CheckPathTraversal(tempName, PathContext.ExeDirectory);

            MergeServiceInstance.MergeConfigFiles(targetFilePath, sourceFilePath);

            // Note: Don't delete temp file here - let PerformPostExtractionConversionAndMerge() check for it to detect
            // that XML was in the update and was merged. It will be cleaned up later.
            Console.WriteLine("Config files merged successfully!");

            // Save merge report, if created
            if (MergeServiceInstance.LastReport != null)
            {
                MergeServiceInstance.LastReport.IsDryRun = false;
                SaveAndLogReport(MergeServiceInstance.LastReport, "Merge report saved:");
            }
        }
        catch (ConfigException ex)
        {
            Console.WriteLine($"Error: {FormatExceptionDetails(ex)}");
            if (MergeServiceInstance.LastReport != null)
            {
                MergeServiceInstance.LastReport.IsDryRun = false;
                SaveAndLogReport(MergeServiceInstance.LastReport, "Error report saved:");
            }
        }
    }

    public override void HandleJsonConfigDuringExtraction(ZipArchiveEntry entry, string targetFilePath)
    {
        // Copy into temp file ready to merge.
        string tempName = $"tempNew_{entry.FullName}";
        PerformCopy(entry, tempName);

        var merger = new JsonConfigMerger();
        try
        {
            // Calculate full path name for temp file
            string sourceFilePath = FilesValidator.CheckPathTraversal(tempName, PathContext.ExeDirectory);

            merger.MergeJsonConfigFiles(targetFilePath, sourceFilePath);

            // Clear temp file
            File.Delete(sourceFilePath);
            Console.WriteLine("JSON config files merged successfully!");

            // Generate and save merge report
            var report = BuildJsonConfigReport(merger, sourceFilePath, targetFilePath, success: true);
            SaveAndLogReport(report, "Merge report saved:");
        }
        catch (ConfigException ex)
        {
            Console.WriteLine($"Error: {FormatExceptionDetails(ex)}");

            // Create and save error report
            var errorReport = BuildJsonConfigReport(
                merger,
                Path.Combine(PathContext.ExeDirectory, tempName),
                targetFilePath,
                success: false,
                ex);
            SaveAndLogReport(errorReport, "Error report saved:");
        }
    }

    public override bool PerformInitialStateMigration()
    {
        // Check if both XML and JSON config files exist initially
        if (!File.Exists(PathContext.XmlConfigPath) || !File.Exists(PathContext.JsonConfigPath))
        {
            return false;
        }

        Console.WriteLine("Detected both XML and JSON configuration files.");
        Console.WriteLine("Performing initial state migration...");
        Console.WriteLine();

        string tempJsonBackupPath = null;
        ConversionReport migrationReport = null;

        try
        {
            // Create temporary backup of existing JSON in case something goes wrong
            tempJsonBackupPath = Path.Combine(PathContext.ExeDirectory, $"temp_json_backup_{Guid.NewGuid()}.json");
            File.Copy(PathContext.JsonConfigPath, tempJsonBackupPath, overwrite: true);

            // Convert XML to temporary JSON
            var converter = new XmlToJsonConfigConverter();
            string tempConvertedJsonPath = CreateTempFilePath("tempInitialMigration");

            converter.ConvertXmlConfigToJson(PathContext.XmlConfigPath, tempConvertedJsonPath, true, true);

            // Merge converted XML (as source) into existing JSON (as target)
            // This gives XML values precedence when merging
            var merger = new JsonConfigMerger();
            merger.MergeJsonConfigFiles(PathContext.JsonConfigPath, tempConvertedJsonPath);

            // Copy license from converted XML to JSON if JSON license is empty
            CopyLicenseIfEmpty(tempConvertedJsonPath);

            Console.WriteLine("Configuration migration completed successfully!");

            // Generate migration report
            migrationReport = BuildInitialStateMigrationReport(converter, merger, tempConvertedJsonPath, success: true);

            // Clean up temp files
            if (File.Exists(tempConvertedJsonPath))
            {
                try { File.Delete(tempConvertedJsonPath); } catch { }
            }

            // Backup the old XML config file since it's been migrated
            BackupOldXmlConfigFile();

            // Save migration report
            migrationReport.IsDryRun = false;
            SaveAndLogReport(migrationReport, "Initial state migration report saved:", "ConfigMigrationReport");

            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error during initial state migration: {FormatExceptionDetails(ex)}");
            Console.WriteLine("Restoring original configuration files...");

            // Restore JSON from temporary backup
            try
            {
                if (tempJsonBackupPath != null && File.Exists(tempJsonBackupPath))
                {
                    File.Copy(tempJsonBackupPath, PathContext.JsonConfigPath, overwrite: true);
                    Console.WriteLine("Original JSON configuration restored.");
                }
            }
            catch (Exception restoreEx)
            {
                Console.WriteLine($"Warning: Could not restore JSON configuration: {FormatExceptionDetails(restoreEx)}");
            }

            // Create error report
            migrationReport = new ConversionReport
            {
                SourcePath = PathContext.XmlConfigPath,
                TargetPath = PathContext.JsonConfigPath,
                Success = false,
                Timestamp = DateTime.Now,
                IsDryRun = false,
                ErrorMessage = FormatExceptionDetails(ex),
                Exception = ex
            };

            migrationReport.Warnings.Add("Initial state migration failed - proceeding with update using existing configuration");
            SaveAndLogReport(migrationReport, "Initial state migration error report saved:");

            return false;
        }
        finally
        {
            // Clean up temporary JSON backup
            if (tempJsonBackupPath != null && File.Exists(tempJsonBackupPath))
            {
                try { File.Delete(tempJsonBackupPath); } catch { }
            }
        }
    }

    public override void PerformPostExtractionConversionAndMerge()
    {
        // Detect current state after extraction
        var state = PathContext.DetectCurrentState();

        // Determine configuration case and handle accordingly
        ConfigurationCase configCase = state.DetermineCase();

        switch (configCase)
        {
            case ConfigurationCase.JsonMerge:
                // Case 3: Initial: JSON, Update: JSON → Merge JSON
                Console.WriteLine("Merging configuration files...");
                HandleJsonMerge();
                break;

            case ConfigurationCase.XmlToJsonUpdate:
                // Case 4: Initial: XML, Update: JSON → Convert XML→JSON, merge with new JSON
                Console.WriteLine("Converting configuration and merging...");
                HandleXmlConversionWithJsonMerge();
                break;

            case ConfigurationCase.NoneToJson:
                // Case 2: Initial: None, Update: JSON → Extract JSON (already in place)
                HandleJsonFromUpdate();
                break;

            case ConfigurationCase.NoAction:
                // Case 1 and other no-action scenarios - no action needed, but generate a minimal report for audit trail
                GenerateNoActionReport();
                break;
        }

        // Cleanup all temp files
        CleanupTemporaryFiles();
    }

    /// <summary>
    /// Build a JSON configuration merge report (success or error case)
    /// </summary>
    private ConversionReport BuildJsonConfigReport(
        JsonConfigMerger merger,
        string sourcePath,
        string targetPath,
        bool success,
        Exception? ex = null)
    {
        var report = new ConversionReport
        {
            SourcePath = sourcePath,
            TargetPath = targetPath,
            Success = success,
            Timestamp = DateTime.Now,
            SectionsConverted = success ? merger.MergedProperties.ToList() : new List<string>(),
            TotalSettingsMapped = success ? merger.NewProperties.Count + merger.MergedProperties.Count : 0,
            IsDryRun = false,
            ErrorMessage = ex != null ? FormatExceptionDetails(ex) : null,
            Exception = ex
        };

        if (success)
        {
            foreach (var prop in merger.NewProperties)
            {
                report.MappedSettings[$"Added: {prop}"] = "New property from source";
            }
        }

        return report;
    }

    /// <summary>
    /// Build a conversion and merge report for XML conversion + JSON merge operations
    /// </summary>
    private ConversionReport BuildConversionAndMergeReport(
        XmlToJsonConfigConverter converter,
        JsonConfigMerger merger,
        string tempJsonPath)
    {
        var report = new ConversionReport
        {
            SourcePath = PathContext.XmlConfigPath,
            TargetPath = PathContext.JsonConfigPath,
            Success = true,
            Timestamp = DateTime.Now,
            IsDryRun = false,
            TotalSettingsMapped = converter.LastReport.TotalSettingsMapped + merger.NewProperties.Count + merger.MergedProperties.Count
        };

        // Include sections from conversion
        report.SectionsConverted.AddRange(converter.LastReport.SectionsConverted);

        // Include sections from merge
        report.SectionsConverted.AddRange(merger.MergedProperties);

        // Map all settings from conversion
        foreach (var setting in converter.LastReport.MappedSettings)
        {
            report.MappedSettings[setting.Key] = setting.Value;
        }

        // Map all settings from merge
        foreach (var prop in merger.NewProperties)
        {
            report.MappedSettings[$"Added: {prop}"] = "New property from source (merge)";
        }

        foreach (var prop in merger.MergedProperties)
        {
            report.MappedSettings[$"Merged: {prop}"] = "Property merged from source";
        }

        // Add unmapped settings if any
        foreach (var unmapped in converter.LastReport.UnmappedSettings)
        {
            report.UnmappedSettings[unmapped.Key] = unmapped.Value;
        }

        report.Warnings.AddRange(converter.LastReport.Warnings);
        report.XmlRenamedToBackup = true;
        report.BackupPath = PathContext.XmlConfigPath + ".bak";

        return report;
    }

    protected override void HandleJsonMerge()
    {
        try
        {
            if (File.Exists(PathContext.TempJsonPath) && File.Exists(PathContext.JsonConfigPath))
            {
                var merger = new JsonConfigMerger();
                merger.MergeJsonConfigFiles(PathContext.JsonConfigPath, PathContext.TempJsonPath);
                Console.WriteLine("Configuration merge completed successfully!");

                // Generate and save merge report
                var report = BuildJsonConfigReport(merger, PathContext.TempJsonPath, PathContext.JsonConfigPath, success: true);
                SaveAndLogReport(report, "Merge report saved:");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Configuration merge failed: {ex.Message}");
        }
    }

    protected override void HandleXmlConversionWithJsonMerge()
    {
        var converter = new XmlToJsonConfigConverter();
        string tempXmlJsonPath = null;
        ConversionReport finalReport = null;
        bool success = false;
        string errorDetails = null;

        try
        {
            tempXmlJsonPath = CreateTempFilePath("tempConversion");
            converter.ConvertXmlConfigToJson(PathContext.XmlConfigPath, tempXmlJsonPath, createBackup: false);

            if (File.Exists(PathContext.TempJsonPath) && File.Exists(tempXmlJsonPath))
            {
                var merger = new JsonConfigMerger();
                merger.MergeJsonConfigFiles(tempXmlJsonPath, PathContext.TempJsonPath);
                File.Copy(tempXmlJsonPath, PathContext.JsonConfigPath, overwrite: true);

                // Generate combined report showing both conversion and merge
                finalReport = BuildConversionAndMergeReport(converter, merger, tempXmlJsonPath);
                success = true;
            }
            else if (File.Exists(tempXmlJsonPath))
            {
                File.Copy(tempXmlJsonPath, PathContext.JsonConfigPath, overwrite: true);

                // Only conversion, no merge
                finalReport = converter.LastReport ?? new ConversionReport
                {
                    SourcePath = PathContext.XmlConfigPath,
                    TargetPath = PathContext.JsonConfigPath,
                    Success = true,
                    Timestamp = DateTime.Now
                };
                success = true;
            }
            else
            {
                // Temp file doesn't exist
                finalReport = new ConversionReport
                {
                    SourcePath = PathContext.XmlConfigPath,
                    TargetPath = PathContext.JsonConfigPath,
                    Success = false,
                    ErrorMessage = "Conversion failed: temporary JSON file was not created",
                    Timestamp = DateTime.Now
                };
            }

            // Explicitly backup the old XML config file with proper error reporting
            BackupOldXmlConfigFile();

            if (success)
            {
                Console.WriteLine("Configuration conversion and merge completed successfully!");
            }
        }
        catch (Exception ex)
        {
            errorDetails = FormatExceptionDetails(ex);
            Console.WriteLine($"Configuration conversion/merge failed: {errorDetails}");

            // Create error report if no report exists yet
            finalReport = finalReport ?? new ConversionReport
            {
                SourcePath = PathContext.XmlConfigPath,
                TargetPath = PathContext.JsonConfigPath,
                Success = false,
                Timestamp = DateTime.Now
            };

            finalReport.Success = false;
            finalReport.ErrorMessage = errorDetails;
            finalReport.Exception = ex;
        }
        finally
        {
            // ALWAYS save the report - this is critical
            if (finalReport != null)
            {
                finalReport.IsDryRun = false;
                string reportMessage = finalReport.Success
                    ? "Conversion and merge report saved:"
                    : "Error report saved:";
                SaveAndLogReport(finalReport, reportMessage);
            }
            else
            {
                // Fallback: if no report was created at all, create a minimal one
                var fallbackReport = new ConversionReport
                {
                    SourcePath = PathContext.XmlConfigPath,
                    TargetPath = PathContext.JsonConfigPath,
                    Success = false,
                    ErrorMessage = "Unexpected error: report could not be generated",
                    Timestamp = DateTime.Now,
                    IsDryRun = false
                };
                SaveAndLogReport(fallbackReport, "Fallback error report saved:");
            }

            // Clean up temp file in finally block to ensure it always happens
            if (tempXmlJsonPath != null && File.Exists(tempXmlJsonPath))
            {
                try
                {
                    File.Delete(tempXmlJsonPath);
                }
                catch
                {
                    // Ignore cleanup errors
                }
            }
        }
    }

    protected override void HandleJsonFromUpdate()
    {
        ConversionReport report = null;
        bool success = false;

        try
        {
            if (File.Exists(PathContext.TempJsonPath) && !File.Exists(PathContext.JsonConfigPath))
            {
                File.Copy(PathContext.TempJsonPath, PathContext.JsonConfigPath);
                success = true;
            }

            Console.WriteLine("Configuration extracted successfully");

            // Generate extraction report
            report = new ConversionReport
            {
                SourcePath = PathContext.TempJsonPath,
                TargetPath = PathContext.JsonConfigPath,
                Success = success,
                Timestamp = DateTime.Now,
                IsDryRun = false,
                TotalSettingsMapped = 1 // Indicate that configuration was extracted
            };

            report.MappedSettings["Configuration"] = "Extracted from update";
            report.SectionsConverted.Add("Configuration extracted");

            SaveAndLogReport(report, "Configuration extraction report saved:");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Warning: Could not finalize JSON configuration: {FormatExceptionDetails(ex)}");

            // Create error report
            report = new ConversionReport
            {
                SourcePath = PathContext.TempJsonPath,
                TargetPath = PathContext.JsonConfigPath,
                Success = false,
                Timestamp = DateTime.Now,
                IsDryRun = false,
                ErrorMessage = FormatExceptionDetails(ex),
                Exception = ex
            };

            SaveAndLogReport(report, "Configuration extraction error report saved:");
        }
    }

    /// <summary>
    /// Build an initial state migration report combining XML conversion and JSON merge
    /// </summary>
    private ConversionReport BuildInitialStateMigrationReport(
        XmlToJsonConfigConverter converter,
        JsonConfigMerger merger,
        string tempConvertedJsonPath,
        bool success)
    {
        var report = new ConversionReport
        {
            SourcePath = PathContext.XmlConfigPath,
            TargetPath = PathContext.JsonConfigPath,
            Success = success,
            Timestamp = DateTime.Now,
            IsDryRun = false,
            TotalSettingsMapped = converter.LastReport.TotalSettingsMapped + merger.NewProperties.Count + merger.MergedProperties.Count
        };

        report.SectionsConverted.AddRange(converter.LastReport.SectionsConverted);
        report.SectionsConverted.AddRange(merger.MergedProperties);

        // Include conversion mappings
        foreach (var setting in converter.LastReport.MappedSettings)
        {
            report.MappedSettings[setting.Key] = setting.Value;
        }

        // Include merge mappings
        foreach (var prop in merger.NewProperties)
        {
            report.MappedSettings[$"Added: {prop}"] = "New property from XML conversion";
        }

        foreach (var prop in merger.MergedProperties)
        {
            report.MappedSettings[$"Merged: {prop}"] = "Property from XML overriding JSON";
        }

        // Include unmapped settings from conversion
        foreach (var unmapped in converter.LastReport.UnmappedSettings)
        {
            report.UnmappedSettings[unmapped.Key] = unmapped.Value;
        }

        report.Warnings.AddRange(converter.LastReport.Warnings);
        report.Warnings.Add("Initial state migration: XML configuration migrated and merged into JSON");
        report.XmlRenamedToBackup = true;
        report.BackupPath = PathContext.XmlConfigPath + ".bak";

        return report;
    }

    /// <summary>
    /// Generate a no-action report for audit trail when no configuration conversion/merge is needed
    /// </summary>
    private void GenerateNoActionReport()
    {
        try
        {
            var report = new ConversionReport
            {
                SourcePath = "N/A",
                TargetPath = "N/A",
                Success = true,
                Timestamp = DateTime.Now,
                IsDryRun = false,
                TotalSettingsMapped = 0
            };

            report.Warnings.Add("No configuration conversion or merge was required");
            report.MappedSettings["Status"] = "No action taken - existing configuration is compatible";

            SaveAndLogReport(report, "Configuration status report saved:");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Could not generate status report: {FormatExceptionDetails(ex)}");
        }
    }

    protected override void PerformCopy(ZipArchiveEntry entry, string? alternativeName)
    {
        var entryFullName = alternativeName ?? entry.FullName;
        string entryFullPath = FilesValidator.CheckPathTraversal(entryFullName, PathContext.ExeDirectory);

        using (var entryStream = entry.Open())
        {
            string exePath = Environment.ProcessPath ?? AppContext.BaseDirectory;
            string exeFullPath = Path.GetFullPath(exePath);

            Console.WriteLine("Saving " + entryFullName);
            if (File.Exists(entryFullPath))
            {
                // If trying to overwrite the current exe (which is in use), use File.Replace
                if (string.Compare(entryFullPath, exeFullPath, StringComparison.OrdinalIgnoreCase) == 0)
                {
                    string bakFileName = entryFullPath + ".bak";
                    string tempFileName = entryFullPath + ".tmp";

                    // Write new version to temp file first
                    using (var tempFileStream = File.Create(tempFileName))
                    {
                        entryStream.CopyTo(tempFileStream);
                    }

                    try
                    {
                        // File.Replace handles in-use files correctly on Windows
                        File.Replace(tempFileName, entryFullPath, bakFileName, ignoreMetadataErrors: true);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Warning: Could not replace in-use file '{entryFullName}': {ex.Message}");
                        // Clean up temp file
                        try { File.Delete(tempFileName); } catch { }
                    }

                    return;
                }
            }

            using (var fileStream = File.Create(entryFullPath))
            {
                entryStream.CopyTo(fileStream);
            }
        }
    }

    /// <summary>
    /// Copy license value from converted XML to JSON if JSON license is empty or missing.
    /// Simple post-merge step to ensure license is preserved during initial state migration.
    /// </summary>
        private void CopyLicenseIfEmpty(string convertedXmlJsonPath)
        {
            try
            {
                // Read both files
                var targetJson = System.Text.Json.Nodes.JsonNode.Parse(System.IO.File.ReadAllText(PathContext.JsonConfigPath)) as System.Text.Json.Nodes.JsonObject;
                var sourceJson = System.Text.Json.Nodes.JsonNode.Parse(System.IO.File.ReadAllText(convertedXmlJsonPath)) as System.Text.Json.Nodes.JsonObject;

                if (targetJson == null || sourceJson == null)
                {
                    return;
                }

                // Get license values
                var targetLicense = GetNestedString(targetJson, "License", "License");
                var sourceLicense = GetNestedString(sourceJson, "License", "License");

                // If target license is empty and source has a license, copy it
                if (string.IsNullOrEmpty(targetLicense) && !string.IsNullOrEmpty(sourceLicense))
                {
                    // Ensure License structure exists in target
                    if (targetJson["License"] == null)
                    {
                        targetJson["License"] = new System.Text.Json.Nodes.JsonObject();
                    }

                    if (targetJson["License"] is System.Text.Json.Nodes.JsonObject licenseObj)
                    {
                        licenseObj["License"] = sourceLicense;
                        System.IO.File.WriteAllText(PathContext.JsonConfigPath, targetJson.ToJsonString(new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
                    }
                }
            }
            catch (Exception ex)
            {
                // Non-fatal: if we can't copy the license, just log and continue
                Console.WriteLine($"[INFO] Could not copy license value during migration: {ex.Message}");
            }
        }

        /// <summary>
        /// Helper to safely get a nested string value from JSON object.
        /// </summary>
        private static string GetNestedString(System.Text.Json.Nodes.JsonObject obj, string level1, string level2)
        {
            if (obj == null || obj[level1] == null)
            {
                return null;
            }

            if (obj[level1] is System.Text.Json.Nodes.JsonObject nested && nested[level2] != null)
            {
                return nested[level2].GetValue<string>();
            }

            return null;
        }
    }
