#nullable enable

namespace PingCastleAutoUpdater.ConfigurationOrchestration;

using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using ConfigurationConversion;
using ConfigurationMerge;

/// <summary>
/// Strategy implementation for dry-run configuration handling.
/// Simulates operations without actually modifying files, generates preview reports.
/// </summary>
public class DryRunConfigurationStrategy : ConfigurationStrategyBase
{
    public DryRunConfigurationStrategy(ConfigurationPathContext pathContext)
        : base(pathContext)
    {
    }

    public override void HandleXmlConfigDuringExtraction(ZipArchiveEntry entry, string targetFilePath)
    {
        Console.WriteLine($"[DRY-RUN] Would merge .config file: {Path.GetFileName(targetFilePath)}");

        // In dry-run mode, only extract PingCastle.exe.config for analysis (skip auto-updater config)
        if (Path.GetFileName(targetFilePath).Equals("PingCastle.exe.config", StringComparison.OrdinalIgnoreCase))
        {
            string tempDryRunPath = Path.Combine(PathContext.ExeDirectory, "DRY_RUN_TEMP_" + Path.GetFileName(targetFilePath));
            try
            {
                using (var e = entry.Open())
                using (var fileStream = File.Create(tempDryRunPath))
                {
                    e.CopyTo(fileStream);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DRY-RUN] Warning: Could not extract file for analysis: {ex.Message}");
            }
        }
    }

    public override void HandleJsonConfigDuringExtraction(ZipArchiveEntry entry, string targetFilePath)
        => Console.WriteLine($"[DRY-RUN] Would merge JSON config file: {Path.GetFileName(targetFilePath)}");

    public override bool PerformInitialStateMigration()
    {
        // Check if both XML and JSON config files exist initially
        if (!File.Exists(PathContext.XmlConfigPath) || !File.Exists(PathContext.JsonConfigPath))
        {
            return false;
        }

        Console.WriteLine("[DRY-RUN] Detected both XML and JSON configuration files.");
        Console.WriteLine("[DRY-RUN] Would perform initial state migration...");
        Console.WriteLine();

        try
        {
            // Simulate XML to JSON conversion - only read files, don't modify them
            var converter = new XmlToJsonConfigConverter();
            string tempConvertedJsonPath = CreateTempFilePath("tempInitialMigration");

            converter.ConvertXmlConfigToJson(PathContext.XmlConfigPath, tempConvertedJsonPath, deleteSourceOnCompletion: false, createBackup: false);

            // Simulate merge - read files without modifying the actual config
            var merger = new JsonConfigMerger();

            // Create a temporary copy of the JSON file for simulation purposes
            string tempJsonBackupPath = CreateTempFilePath("tempJsonBackup");
            File.Copy(PathContext.JsonConfigPath, tempJsonBackupPath, overwrite: true);

            try
            {
                // Merge into the temporary copy only, not the actual file
                merger.MergeJsonConfigFiles(tempJsonBackupPath, tempConvertedJsonPath);
            }
            finally
            {
                // Clean up the temporary JSON backup
                if (File.Exists(tempJsonBackupPath))
                {
                    try
                    {
                        File.Delete(tempJsonBackupPath);
                    }
                    catch
                    {
                    }
                }
            }

            Console.WriteLine("[DRY-RUN] Configuration migration would complete successfully!");
            Console.WriteLine();

            // Generate dry-run migration report
            var report = BuildDryRunInitialStateMigrationReport(converter, merger, tempConvertedJsonPath, success: true);

            // Clean up temp file
            if (File.Exists(tempConvertedJsonPath))
            {
                try
                {
                    File.Delete(tempConvertedJsonPath);
                }
                catch
                {
                }
            }

            SaveAndLogReport(report, "Initial state migration preview report saved:", "InitialSettingsUpdate");

            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[DRY-RUN] Could not preview initial state migration: {FormatExceptionDetails(ex)}");

            // Create error preview report
            var errorReport = new ConversionReport
            {
                SourcePath = PathContext.XmlConfigPath,
                TargetPath = PathContext.JsonConfigPath,
                Success = false,
                Timestamp = DateTime.Now,
                IsDryRun = true,
                ErrorMessage = FormatExceptionDetails(ex),
                Exception = ex
            };

            errorReport.Warnings.Add("Initial state migration preview failed");
            SaveAndLogReport(errorReport, "Initial state migration error preview report saved:");

            return false;
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
                Console.WriteLine("[DRY-RUN] Would merge JSON configuration files");
                HandleJsonMerge();
                break;

            case ConfigurationCase.XmlToJsonUpdate:
                // Case 4: Initial: XML, Update: JSON → Convert XML→JSON, merge with new JSON
                Console.WriteLine("[DRY-RUN] Would convert XML configuration to JSON and merge");
                HandleXmlConversionWithJsonMerge();
                break;

            case ConfigurationCase.NoneToJson:
                // Case 2: Initial: None, Update: JSON → Extract JSON
                HandleJsonFromUpdate();
                break;

            case ConfigurationCase.NoAction:
                // Case 1 and other no-action scenarios - generate preview report for audit trail
                GenerateDryRunNoActionReport();
                break;
        }

        // Cleanup all temporary files
        CleanupTemporaryFiles();
    }

    protected override void HandleJsonMerge()
    {
        Console.WriteLine("[DRY-RUN] Would merge JSON configuration files");

        try
        {
            if (File.Exists(PathContext.TempJsonPath) && File.Exists(PathContext.JsonConfigPath))
            {
                var merger = new JsonConfigMerger();

                // Simulate the merge to generate preview report
                merger.MergeJsonConfigFiles(PathContext.JsonConfigPath, PathContext.TempJsonPath);

                // Generate and save preview report
                var report = BuildDryRunJsonMergeReport(
                    merger,
                    PathContext.TempJsonPath,
                    PathContext.JsonConfigPath,
                    success: true);
                SaveAndLogReport(report, "Merge preview report saved:");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[DRY-RUN] Could not preview merge: {FormatExceptionDetails(ex)}");
        }
    }

    protected override void HandleXmlConversionWithJsonMerge()
    {
        Console.WriteLine("[DRY-RUN] Would convert XML configuration to JSON and merge");

        if (!File.Exists(PathContext.XmlConfigPath))
        {
            return;
        }

        var converter = new XmlToJsonConfigConverter();
        try
        {
            string tempJsonPath = CreateTempFilePath("tempConversion");
            converter.ConvertXmlConfigToJson(PathContext.XmlConfigPath, tempJsonPath, createBackup: false);

            if (File.Exists(PathContext.TempJsonPath))
            {
                var merger = new JsonConfigMerger();
                merger.MergeJsonConfigFiles(tempJsonPath, PathContext.TempJsonPath);

                // Generate combined report showing both conversion and merge
                var report = BuildDryRunConversionAndMergeReport(converter, merger, tempJsonPath);
                SaveAndLogReport(report, "Conversion and merge preview report saved:");
            }
            else
            {
                // Only conversion, no merge
                converter.LastReport.IsDryRun = true;
                SaveAndLogReport(converter.LastReport, "Conversion preview report saved:");
            }

            // Clean up temp file
            if (File.Exists(tempJsonPath))
            {
                File.Delete(tempJsonPath);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[DRY-RUN] Could not preview conversion and merge: {FormatExceptionDetails(ex)}");
            if (converter.LastReport != null)
            {
                converter.LastReport.IsDryRun = true;
                SaveAndLogReport(converter.LastReport, "Error preview report saved:");
            }
        }
    }

    protected override void HandleJsonFromUpdate()
    {
        Console.WriteLine("[DRY-RUN] Would extract JSON configuration from update");

        try
        {
            // Generate dry-run preview report for extraction
            var report = new ConversionReport
            {
                SourcePath = PathContext.TempJsonPath,
                TargetPath = PathContext.JsonConfigPath,
                Success = true,
                Timestamp = DateTime.Now,
                IsDryRun = true,
                TotalSettingsMapped = 1
            };

            report.MappedSettings["Configuration"] = "Would be extracted from update";
            report.SectionsConverted.Add("Configuration extraction");

            SaveAndLogReport(report, "Configuration extraction preview report saved:");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[DRY-RUN] Could not generate extraction preview: {FormatExceptionDetails(ex)}");
        }
    }

    /// <summary>
    /// Build a dry-run initial state migration report combining XML conversion and JSON merge
    /// </summary>
    private ConversionReport BuildDryRunInitialStateMigrationReport(
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
            IsDryRun = true,
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
            report.MappedSettings[$"Merged: {prop}"] = "Property from XML would override JSON";
        }

        // Include unmapped settings from conversion
        foreach (var unmapped in converter.LastReport.UnmappedSettings)
        {
            report.UnmappedSettings[unmapped.Key] = unmapped.Value;
        }

        report.Warnings.AddRange(converter.LastReport.Warnings);
        report.Warnings.Add("Initial state migration: XML would be migrated and merged into JSON");

        return report;
    }

    /// <summary>
    /// Generate a no-action preview report for audit trail when no configuration conversion/merge is needed
    /// </summary>
    private void GenerateDryRunNoActionReport()
    {
        try
        {
            var report = new ConversionReport
            {
                SourcePath = "N/A",
                TargetPath = "N/A",
                Success = true,
                Timestamp = DateTime.Now,
                IsDryRun = true,
                TotalSettingsMapped = 0
            };

            report.Warnings.Add("No configuration conversion or merge would be required");
            report.MappedSettings["Status"] = "No action would be taken - existing configuration is compatible";

            SaveAndLogReport(report, "Configuration status preview report saved:");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[DRY-RUN] Could not generate status preview: {FormatExceptionDetails(ex)}");
        }
    }

    protected override void PerformCopy(ZipArchiveEntry entry, string? alternativeName)
    {
        var entryFullName = alternativeName ?? entry.FullName;
        Console.WriteLine("[DRY-RUN] Would save " + entryFullName);
    }

    /// <summary>
    /// Override to simulate backup of XML config file during dry-run
    /// </summary>
    protected override void BackupOldXmlConfigFile()
    {
        Console.WriteLine($"[DRY-RUN] Would archive old configuration file: {Path.GetFileName(PathContext.XmlConfigPath)} → {Path.GetFileName(PathContext.XmlConfigPath)}.bak");
    }

    /// <summary>
    /// Build a dry-run preview report for JSON merge operations
    /// </summary>
    private ConversionReport BuildDryRunJsonMergeReport(
        JsonConfigMerger merger,
        string sourcePath,
        string targetPath,
        bool success)
    {
        var report = new ConversionReport
        {
            SourcePath = sourcePath,
            TargetPath = targetPath,
            Success = success,
            Timestamp = DateTime.Now,
            SectionsConverted = success ? merger.MergedProperties.ToList() : new List<string>(),
            TotalSettingsMapped = success ? merger.NewProperties.Count + merger.MergedProperties.Count : 0,
            IsDryRun = true
        };

        if (success)
        {
            foreach (var prop in merger.NewProperties)
            {
                report.MappedSettings[$"Added: {prop}"] = "New property from source";
            }

            foreach (var prop in merger.MergedProperties)
            {
                report.MappedSettings[$"Merged: {prop}"] = "Property merged from source";
            }

            if (merger.NewProperties.Count == 0 && merger.MergedProperties.Count == 0)
            {
                report.Warnings.Add("No changes would be made - configuration files are identical");
            }
        }

        return report;
    }

    /// <summary>
    /// Build a dry-run preview report for XML conversion + JSON merge operations
    /// </summary>
    private ConversionReport BuildDryRunConversionAndMergeReport(
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
            IsDryRun = true,
            TotalSettingsMapped = converter.LastReport.TotalSettingsMapped + merger.NewProperties.Count + merger.MergedProperties.Count
        };

        // Include sections from conversion
        report.SectionsConverted.AddRange(converter.LastReport.SectionsConverted);

        // Include sections from merge
        report.SectionsConverted.AddRange(merger.MergedProperties);

        // Map all settings
        foreach (var setting in converter.LastReport.MappedSettings)
        {
            report.MappedSettings[setting.Key] = setting.Value;
        }

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

        return report;
    }
}
