#nullable enable

namespace PingCastleAutoUpdater.ConfigurationOrchestration;

using System;
using System.IO;
using System.IO.Compression;
using ConfigurationConversion;
using ConfigurationMerge;

/// <summary>
/// Base class for configuration orchestration strategies.
/// Provides shared utilities and defines the template for concrete implementations.
/// </summary>
public abstract class ConfigurationStrategyBase : IConfigurationStrategy
{
    protected readonly ConfigurationPathContext PathContext;
    protected readonly ConfigMergeService MergeServiceInstance;

    protected ConfigurationStrategyBase(ConfigurationPathContext pathContext)
    {
        PathContext = pathContext ?? throw new ArgumentNullException(nameof(pathContext));

        // Instantiate dependencies (manual DI pattern matching existing architecture)
        MergeServiceInstance = new ConfigMergeService(
            new ConfigLoader(),
            new ConfigMerger(),
            new ConfigSaver());
    }

    public abstract void HandleXmlConfigDuringExtraction(ZipArchiveEntry entry, string targetFilePath);
    public abstract void HandleJsonConfigDuringExtraction(ZipArchiveEntry entry, string targetFilePath);
    public abstract void PerformPostExtractionConversionAndMerge();
    public abstract bool PerformInitialStateMigration();

    /// <summary>
    /// Format exception details for user-friendly console output
    /// </summary>
    protected static string FormatExceptionDetails(Exception ex)
    {
        var details = new System.Text.StringBuilder();

        // For FileNotFoundException, FileName property contains the path, not Message
        if (ex is FileNotFoundException fileEx)
        {
            string message = !string.IsNullOrEmpty(fileEx.Message) ? fileEx.Message : "File not found";
            string filename = !string.IsNullOrEmpty(fileEx.FileName) ? fileEx.FileName : "(unknown file)";
            details.AppendLine($"{ex.GetType().Name}: {message}");
            details.AppendLine($"File: {filename}");
        }
        else
        {
            details.AppendLine($"{ex.GetType().Name}: {ex.Message}");
        }

        if (ex.InnerException != null)
        {
            details.AppendLine($"Inner Exception: {ex.InnerException.GetType().Name}: {ex.InnerException.Message}");
        }

        if (!string.IsNullOrEmpty(ex.StackTrace))
        {
            details.AppendLine($"Location: {ex.StackTrace.Split(new[] { Environment.NewLine }, StringSplitOptions.None)[0]}");
        }

        return details.ToString().TrimEnd();
    }

    /// <summary>
    /// Save a report and log the full path, or log error if save fails
    /// </summary>
    protected void SaveAndLogReport(ConversionReport report, string message, string reportBaseName = "ConversionReport")
    {
        try
        {
            string reportPath = report.SaveReportToFile(PathContext.ExeDirectory, reportBaseName);
            string fullReportPath = Path.GetFullPath(reportPath);
            Console.WriteLine($"{message} {fullReportPath}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Could not save report: {FormatExceptionDetails(ex)}");
        }
    }

    /// <summary>
    /// Create a temporary file path with a unique GUID
    /// </summary>
    protected string CreateTempFilePath(string prefix)
    {
        string filename = $"{prefix}_{Guid.NewGuid()}.json";
        return Path.Combine(PathContext.ExeDirectory, filename);
    }

    /// <summary>
    /// Backup the old XML configuration file by renaming it with .bak extension.
    /// This preserves the original configuration for potential recovery.
    /// </summary>
    protected virtual void BackupOldXmlConfigFile()
    {
        try
        {
            if (File.Exists(PathContext.XmlConfigPath))
            {
                string backupPath = PathContext.XmlConfigPath + ".bak";
                // Overwrite existing backup if present
                if (File.Exists(backupPath))
                {
                    File.Delete(backupPath);
                }

                File.Move(PathContext.XmlConfigPath, backupPath);
                Console.WriteLine($"Archived old configuration file: {Path.GetFileName(PathContext.XmlConfigPath)} → {Path.GetFileName(backupPath)}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[WARNING] Could not backup old configuration file '{Path.GetFileName(PathContext.XmlConfigPath)}': {FormatExceptionDetails(ex)}");
        }
    }

    /// <summary>
    /// Clean up all temporary files created during processing
    /// </summary>
    protected void CleanupTemporaryFiles()
    {
        try
        {
            var patterns = new[] { "tempNew_*", "tempConversion_*", "DRY_RUN_TEMP_*" };
            foreach (var pattern in patterns)
            {
                var tempFiles = Directory.GetFiles(PathContext.ExeDirectory, pattern);
                foreach (var tempFile in tempFiles)
                {
                    try
                    {
                        File.Delete(tempFile);
                    }
                    catch
                    {
                        // Do not fail if we fail to delete a file
                    }
                }
            }
        }
        catch
        {
            // Continue regardless.
        }
    }

    /// <summary>
    /// Handle JSON merge operations - behavior differs by strategy
    /// </summary>
    protected abstract void HandleJsonMerge();

    /// <summary>
    /// Handle XML conversion and JSON merge - behavior differs by strategy
    /// </summary>
    protected abstract void HandleXmlConversionWithJsonMerge();

    /// <summary>
    /// Handle extraction of JSON from update when no initial config exists - behavior differs by strategy
    /// </summary>
    protected abstract void HandleJsonFromUpdate();

    /// <summary>
    /// Copy a file from zip entry - behavior differs by strategy
    /// </summary>
    protected abstract void PerformCopy(ZipArchiveEntry entry, string? alternativeName);
}
