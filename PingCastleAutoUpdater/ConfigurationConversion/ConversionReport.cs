namespace PingCastleAutoUpdater.ConfigurationConversion
{
    using System;
    using System.Collections.Generic;
    using System.Text;

    /// <summary>
    /// Detailed report of XML to JSON configuration conversion operation.
    /// </summary>
    public class ConversionReport
    {
        public ConversionReport()
        {
            Timestamp = DateTime.Now;
            MappedSettings = new Dictionary<string, string>();
            UnmappedSettings = new Dictionary<string, object>();
            Warnings = new List<string>();
            SectionsConverted = new List<string>();
        }

        /// <summary>When the conversion occurred</summary>
        public DateTime Timestamp { get; set; }

        /// <summary>Was the conversion successful?</summary>
        public bool Success { get; set; }

        /// <summary>Error message if conversion failed</summary>
        public string ErrorMessage { get; set; }

        /// <summary>Exception details if conversion failed</summary>
        public Exception Exception { get; set; }

        /// <summary>Path to source XML file</summary>
        public string SourcePath { get; set; }

        /// <summary>Path to target JSON file</summary>
        public string TargetPath { get; set; }

        /// <summary>Whether a backup was created</summary>
        public bool BackupCreated { get; set; }

        /// <summary>Path to backup file created</summary>
        public string BackupPath { get; set; }

        /// <summary>Total settings mapped from XML to JSON</summary>
        public int TotalSettingsMapped { get; set; }

        /// <summary>Detailed mapping of each XML setting to JSON</summary>
        public Dictionary<string, string> MappedSettings { get; set; }

        /// <summary>Custom XML elements that couldn't be mapped cleanly to JSON</summary>
        public Dictionary<string, object> UnmappedSettings { get; set; }

        /// <summary>Warnings encountered during conversion</summary>
        public List<string> Warnings { get; set; }

        /// <summary>Configuration sections that were converted</summary>
        public List<string> SectionsConverted { get; set; }

        /// <summary>Whether original XML file was renamed to .backup</summary>
        public bool XmlRenamedToBackup { get; set; }

        /// <summary>Whether this report was generated in dry-run mode</summary>
        public bool IsDryRun { get; set; }

        /// <summary>
        /// Generate a human-readable report string
        /// </summary>
        public string GenerateDetailedReport()
        {
            var sb = new StringBuilder();

            sb.AppendLine("===================================================================");
            sb.AppendLine("            CONFIGURATION MIGRATION REPORT");
            sb.AppendLine("===================================================================");
            sb.AppendLine();

            sb.AppendLine($"Timestamp: {Timestamp:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"Source: {SourcePath}");
            sb.AppendLine($"Target: {TargetPath}");
            sb.AppendLine();

            sb.AppendLine("-------------------------------------------------------------------");
            sb.AppendLine("CONVERSION SUMMARY");
            sb.AppendLine("-------------------------------------------------------------------");

            if (Success)
            {
                sb.AppendLine($"[OK] Status: SUCCESSFUL");
                sb.AppendLine($"[OK] Sections Converted: {SectionsConverted.Count}");
                sb.AppendLine($"[OK] Settings Mapped: {TotalSettingsMapped}");
                sb.AppendLine($"[OK] Custom Elements Found: {UnmappedSettings.Count}");
                if (BackupCreated)
                {
                    sb.AppendLine($"[OK] JSON Backup Created: {System.IO.Path.GetFileName(BackupPath)}");
                }

                if (XmlRenamedToBackup)
                {
                    sb.AppendLine($"[OK] Original XML archived as: PingCastle.exe.config.bak");
                }
            }
            else
            {
                sb.AppendLine($"[FAILED] Status: FAILED");
                sb.AppendLine($"[FAILED] Error: {ErrorMessage}");
                if (Exception != null)
                {
                    sb.AppendLine($"[FAILED] Exception: {Exception.GetType().Name}");
                }
            }

            sb.AppendLine();

            if (SectionsConverted.Count > 0)
            {
                sb.AppendLine("-------------------------------------------------------------------");
                sb.AppendLine("SECTIONS CONVERTED");
                sb.AppendLine("-------------------------------------------------------------------");
                foreach (var section in SectionsConverted)
                {
                    sb.AppendLine($"  - {section}");
                }

                sb.AppendLine();
            }

            if (MappedSettings.Count > 0)
            {
                sb.AppendLine("-------------------------------------------------------------------");
                sb.AppendLine("DETAILED MAPPING (XML -> JSON)");
                sb.AppendLine("-------------------------------------------------------------------");
                foreach (var kvp in MappedSettings)
                {
                    sb.AppendLine($"  {kvp.Key}");
                    sb.AppendLine($"    -> {kvp.Value}");
                }

                sb.AppendLine();
            }

            if (UnmappedSettings.Count > 0)
            {
                sb.AppendLine("-------------------------------------------------------------------");
                sb.AppendLine("CUSTOM/UNMAPPED SETTINGS");
                sb.AppendLine("-------------------------------------------------------------------");
                sb.AppendLine($"[WARNING] Found {UnmappedSettings.Count} unmapped custom element(s):");
                foreach (var kvp in UnmappedSettings)
                {
                    sb.AppendLine($"  - {kvp.Key}");
                    sb.AppendLine($"    Value: {kvp.Value}");
                }

                sb.AppendLine();
                sb.AppendLine("  Action: Preserved in JSON field \"_unmappedXmlSettings\"");
                sb.AppendLine("  Note: PingCastle may not use these settings. Verify if needed.");
                sb.AppendLine();
            }

            if (SectionsConverted.Count > 0 || MappedSettings.Count > 0)
            {
                sb.AppendLine("-------------------------------------------------------------------");
                sb.AppendLine("MERGE SUMMARY - DATA CHANGES");
                sb.AppendLine("-------------------------------------------------------------------");

                // Identify added items (those prefixed with "Added:")
                var addedSections = new List<string>();
                var mergedSections = new List<string>();

                foreach (var kvp in MappedSettings)
                {
                    if (kvp.Key.StartsWith("Added:"))
                    {
                        string sectionName = kvp.Key.Substring("Added: ".Length);
                        addedSections.Add(sectionName);
                    }
                }

                // Sections that appear in SectionsConverted but not in added items are merged
                foreach (var section in SectionsConverted)
                {
                    if (!addedSections.Contains(section))
                    {
                        mergedSections.Add(section);
                    }
                }

                if (addedSections.Count > 0)
                {
                    sb.AppendLine($"- NEW SECTIONS/SETTINGS ADDED: {addedSections.Count}");
                    foreach (var section in addedSections)
                    {
                        sb.AppendLine($"    [OK] {section}");
                    }

                    sb.AppendLine();
                }

                if (mergedSections.Count > 0)
                {
                    sb.AppendLine($"- EXISTING SECTIONS MERGED/UPDATED: {mergedSections.Count}");
                    foreach (var section in mergedSections)
                    {
                        sb.AppendLine($"    -> {section}");
                    }

                    sb.AppendLine("    (Existing values preserved, new defaults added to configuration)");
                    sb.AppendLine();
                }

                sb.AppendLine($"TOTAL: {TotalSettingsMapped} setting(s) processed across {SectionsConverted.Count} section(s)");
                sb.AppendLine();
            }

            if (Warnings.Count > 0)
            {
                sb.AppendLine("-------------------------------------------------------------------");
                sb.AppendLine("WARNINGS");
                sb.AppendLine("-------------------------------------------------------------------");
                foreach (var warning in Warnings)
                {
                    sb.AppendLine($"[WARNING] {warning}");
                }

                sb.AppendLine();
            }

            sb.AppendLine("-------------------------------------------------------------------");
            sb.AppendLine("NEXT STEPS / ACTION ITEMS");
            sb.AppendLine("-------------------------------------------------------------------");
            if (Success)
            {
                sb.AppendLine("1. REVIEW: Verify migrated values in appsettings.console.json");
                if (UnmappedSettings.Count > 0)
                {
                    sb.AppendLine("2. VERIFY: Unmapped custom settings. See _unmappedXmlSettings.");
                }

                sb.AppendLine("3. TEST: Run PingCastle.exe to verify all features work");
                sb.AppendLine("4. BACKUP: Archive files (.bak) are preserved for recovery if needed");
                if (XmlRenamedToBackup)
                {
                    sb.AppendLine("   - Original XML backed up as: PingCastle.exe.config.bak");
                }

                if (BackupCreated)
                {
                    sb.AppendLine("   - JSON backup available as: appsettings.console.json.bak");
                }
            }
            else
            {
                sb.AppendLine("1. INVESTIGATE: See error message and exception details above");
                sb.AppendLine("2. REVIEW: Original configuration files remain unchanged");
                sb.AppendLine("3. RETRY: Fix issue and try again, or contact support");
            }

            sb.AppendLine();

            // Only include recovery instructions for actual conversions, not dry-runs
            if (!IsDryRun)
            {
                sb.AppendLine("-------------------------------------------------------------------");
                sb.AppendLine("RECOVERY & RESTORATION");
                sb.AppendLine("-------------------------------------------------------------------");
                sb.AppendLine("Archive files (.bak) are created as recovery points and can be");
                sb.AppendLine("restored if needed:");
                sb.AppendLine();

                if (XmlRenamedToBackup)
                {
                    sb.AppendLine("  TO RESTORE ORIGINAL XML CONFIGURATION:");
                    sb.AppendLine("  1. Rename: PingCastle.exe.config.bak → PingCastle.exe.config");
                    sb.AppendLine("  2. Verify original settings are correct");
                    sb.AppendLine("  3. Run PingCastleAutoUpdater again if needed");
                    sb.AppendLine();
                }

                if (BackupCreated)
                {
                    sb.AppendLine("  TO RESTORE JSON CONFIGURATION FROM BACKUP:");
                    sb.AppendLine("  1. Delete current: appsettings.console.json");
                    sb.AppendLine("  2. Rename: appsettings.console.json.bak → appsettings.console.json");
                    sb.AppendLine("  3. Verify configuration is correct before running PingCastle");
                    sb.AppendLine();
                }

                sb.AppendLine("IMPORTANT: Archive files (.bak) are preserved indefinitely and");
                sb.AppendLine("are NOT automatically deleted. You can safely remove them");
                sb.AppendLine("after confirming the migration was successful.");
                sb.AppendLine();
            }

            sb.AppendLine("===================================================================");

            return sb.ToString();
        }

        /// <summary>
        /// Save the report to a timestamped file in the same directory as the configuration
        /// </summary>
        /// <param name="configDirectory">Directory where configuration files are located</param>
        /// <returns>Path to the saved report file</returns>
        public string SaveReportToFile(string configDirectory, string fileBaseName)
        {
            if (string.IsNullOrEmpty(configDirectory))
            {
                throw new ArgumentException("Config directory cannot be null or empty");
            }

            string timestamp = Timestamp.ToString("yyyyMMdd_HHmmss");
            string reportFileName = Success
                ? $"{fileBaseName}_{timestamp}.txt"
                : $"ERROR_{timestamp}.txt";

            string reportPath = System.IO.Path.Combine(configDirectory, reportFileName);

            string reportContent = GenerateDetailedReport();
            System.IO.File.WriteAllText(reportPath, reportContent);

            return reportPath;
        }
    }
}
