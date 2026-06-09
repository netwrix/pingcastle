using PingCastleAutoUpdater.ConfigurationConversion;
using PingCastleAutoUpdater.ConfigurationMerge;
using PingCastleAutoUpdater.ConfigurationOrchestration;
using PingCastleCommon;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Text.Json;
using System.Threading.Tasks;

namespace PingCastleAutoUpdater
{
    class Program
    {
        private static async Task Main(string[] args)
        {
            Program program = new Program();
            await program.RunAsync(args);
        }

        bool forceDownload = false;
        bool preview = false;
        bool dryRun = false;
        int numberOfDaysToWait = 0;
        string releaseInfoUrl = "https://api.github.com/repos/netwrix/pingcastle/releases";

        private async Task RunAsync(string[] args)
        {
            Trace.WriteLine("Before parsing arguments");
            var parseResult = UpdaterLogic.ParseArguments(args);
            if (parseResult.ShowHelp)
            {
                DisplayHelp();
                return;
            }
            if (!parseResult.Success)
            {
                WriteInRed(parseResult.Error);
                DisplayHelp();
                return;
            }
            forceDownload = parseResult.ForceDownload;
            preview = parseResult.Preview;
            dryRun = parseResult.DryRun;
            numberOfDaysToWait = parseResult.WaitForDays;
            releaseInfoUrl = parseResult.ApiUrl;
            Console.WriteLine("Do not forget that there are other command line switches like --help that you can use");
            Console.WriteLine("Running on " + Environment.Version);
            Console.WriteLine();

            Release release = await GetLatestReleaseFromUpdateUrlAsync();
            if (release == null)
                return;

            string currentVersion = GetCurrentVersionFromExecutable();

            // Initialize configuration orchestrator for pre-update migration
            string exePath = Environment.ProcessPath ?? AppContext.BaseDirectory;
            string exeDirectory = Path.GetDirectoryName(exePath);
            var pathContext = new ConfigurationPathContext(exeDirectory);
            var configOrchestrator = new ConfigurationOrchestrationService(pathContext, dryRun);

            // Perform initial state migration if both XML and JSON configs exist
            // This should happen regardless of whether an update is needed
            bool migrationPerformed = configOrchestrator.PerformInitialStateMigration();
            if (migrationPerformed)
            {
                Console.WriteLine("Initial configuration state migration completed.");
                Console.WriteLine();
            }

            if (!IsUpdateRequired(currentVersion, release.name))
            {
                Console.WriteLine("Update is not required. Program is stopping.");
                return;
            }
            string downloadUrl = release.assets.First().browser_download_url;
            Console.WriteLine("Downloading " + downloadUrl);
            Console.WriteLine();

            ProceedReleaseInstall(downloadUrl, dryRun);
        }

        /// <summary>
        /// Returns PingCastle.exe version if it's found in the same directory
        /// Otherwise returns an empty string
        /// </summary>
        /// <returns>PingCastle.exe version or an empty string</returns>
        private string GetCurrentVersionFromExecutable()
        {
            // First, try to get version from pingcastle.exe in the same directory
            string exePath = Environment.ProcessPath ?? AppContext.BaseDirectory;
            string exeDirectory = Path.GetDirectoryName(exePath);
            string pingCastleExePath = Path.Combine(exeDirectory, "pingcastle.exe");
            if (File.Exists(pingCastleExePath))
            {
                try
                {
                    // Use FileVersionInfo to read from the PE file's version resource
                    // This works with both traditional and single-file published executables
                    var fileVersionInfo = FileVersionInfo.GetVersionInfo(pingCastleExePath);
                    if (!string.IsNullOrEmpty(fileVersionInfo.FileVersion))
                    {
                        Console.WriteLine($"Using PingCastle version: `{fileVersionInfo.FileVersion}`");
                        return fileVersionInfo.FileVersion;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Warning: Could not read version from pingcastle.exe: " + ex.Message);
                }
            }
            else
            {
                Console.WriteLine("No pingcastle.exe found");
            }

            return string.Empty;
        }

        private async Task<Release> GetLatestReleaseFromUpdateUrlAsync()
        {
            Console.WriteLine("Getting the list of releases");
            string releaseInfo = await GetFromUrlAsync(releaseInfoUrl);
            Console.WriteLine("Done");

            var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
            IEnumerable<Release> releases = JsonSerializer.Deserialize<List<Release>>(releaseInfo, options);

            var release = UpdaterLogic.FilterAndSortReleases(releases, preview, numberOfDaysToWait);
            if (release == null)
                Console.WriteLine("There is no release matching the requirements");
            else
                Console.WriteLine("Latest release is: " + release.name);

            return release;
        }

        // Returns JSON string
        private static async Task<string> GetFromUrlAsync(string url)
        {
            // GitHub forces TLS 1.2 which is not enabled by default in .net
            System.Net.ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
            Version version = Assembly.GetExecutingAssembly().GetName().Version;
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.UserAgent = "PingCastleAutoUpdater " + version;
            try
            {
                WebResponse response = await request.GetResponseAsync();
                using (Stream responseStream = response.GetResponseStream())
                {
                    StreamReader reader = new StreamReader(responseStream, System.Text.Encoding.UTF8);
                    return await reader.ReadToEndAsync();
                }
            }
            catch (WebException ex)
            {
                HandleWebException(ex, "Network");
                throw;
            }
        }

        private static void HandleWebException(WebException ex, string operationContext)
        {
            WebResponse errorResponse = ex.Response;
            if (errorResponse != null)
            {
                using (Stream responseStream = errorResponse.GetResponseStream())
                {
                    if (responseStream != null)
                    {
                        StreamReader reader = new StreamReader(responseStream, System.Text.Encoding.GetEncoding("utf-8"));
                        string errorText = reader.ReadToEnd();
                        WriteInRed($"{operationContext} error: {errorText}");
                    }
                }
            }
            else
            {
                WriteInRed($"{operationContext} error: {ex.Message}");
            }
        }

        private bool IsUpdateRequired(string currentVersion, string latestVersion)
        {
            return UpdaterLogic.IsUpdateRequired(currentVersion, latestVersion, forceDownload);
        }


        private static void WriteInRed(string data)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(data);
            Trace.WriteLine("[Red]" + data);
            Console.ResetColor();
        }

        private static void BackupExistingConfigurations(ConfigurationPathContext pathContext, bool dryRun)
        {
            if (dryRun) return;

            if (File.Exists(pathContext.JsonConfigPath))
            {
                try
                {
                    File.Copy(pathContext.JsonConfigPath, pathContext.JsonBackupPath, overwrite: true);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Warning: Could not backup existing JSON config: {ex.Message}");
                }
            }

            if (File.Exists(pathContext.XmlConfigPath))
            {
                try
                {
                    File.Copy(pathContext.XmlConfigPath, pathContext.XmlBackupPath, overwrite: true);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Warning: Could not backup existing XML config: {ex.Message}");
                }
            }
        }

        static void ProceedReleaseInstall(string url, bool dryRun)
        {
            Version version = Assembly.GetExecutingAssembly().GetName().Version;
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.UserAgent = "PingCastleAutoUpdater " + version.ToString();

            // Initialize configuration orchestrator (declare outside try block so it's available after)
            string exePath = Environment.ProcessPath ?? AppContext.BaseDirectory;
            string exeDirectory = Path.GetDirectoryName(exePath);
            var pathContext = new ConfigurationPathContext(exeDirectory);
            var configOrchestrator = new ConfigurationOrchestrationService(pathContext, dryRun);

            try
            {
                if (dryRun)
                {
                    Console.WriteLine("[DRY-RUN] No files will be modified. Analyzing update contents...");
                    Console.WriteLine();
                }

                // Backup existing configurations
                BackupExistingConfigurations(pathContext, dryRun);

                WebResponse response = request.GetResponse();
                using (Stream responseStream = response.GetResponseStream())
                using (var archive = new ZipArchive(responseStream, ZipArchiveMode.Read))
                {
                    foreach (var entry in archive.Entries)
                    {
                        FilesValidator.CheckPathTraversal(entry.FullName);
                        var targetFilePath = Path.GetFullPath(entry.FullName);
                        // do not save .config file except if it doesn't exists
                        // and do not overwrite the updater file because it's running !
                        string appConfigFile = AppDomain.CurrentDomain.FriendlyName + ".config";
                        if (targetFilePath.EndsWith(".config", StringComparison.OrdinalIgnoreCase)
                            && !Path.GetFileName(targetFilePath).Equals(appConfigFile, StringComparison.OrdinalIgnoreCase))
                        {
                            // Copy if not present.
                            if (!File.Exists(targetFilePath))
                            {
                                // In dry-run mode with existing JSON, extract PingCastle.exe.config for analysis
                                if (dryRun && Path.GetFileName(targetFilePath).Equals("PingCastle.exe.config", StringComparison.OrdinalIgnoreCase)
                                    && File.Exists(pathContext.JsonConfigPath))
                                {
                                    configOrchestrator.HandleXmlConfigDuringExtraction(entry, targetFilePath);
                                }
                                else
                                {
                                    performCopy(entry, null, dryRun);
                                }
                                continue;
                            }

                            configOrchestrator.HandleXmlConfigDuringExtraction(entry, targetFilePath);
                        }
                        else if (Path.GetFileName(targetFilePath).Equals("appsettings.console.json", StringComparison.OrdinalIgnoreCase))
                        {
                            // If JSON backup exists, we'll handle conversion after extraction
                            if (!dryRun && File.Exists(pathContext.JsonBackupPath))
                            {
                                // Don't merge the new JSON from zip yet - we'll convert XML and merge instead
                                performCopy(entry, null, dryRun);
                                continue;
                            }

                            // Copy if not present.
                            if (!File.Exists(targetFilePath))
                            {
                                performCopy(entry, null, dryRun);
                                continue;
                            }

                            configOrchestrator.HandleJsonConfigDuringExtraction(entry, targetFilePath);
                        }
                        else
                        {
                            performCopy(entry, null, dryRun);
                        }
                    }
                }
            }
            catch (WebException ex)
            {
                HandleWebException(ex, "Download");
                throw;
            }

            // After extraction, perform conversion and merge if needed
            configOrchestrator.PerformPostExtractionConversionAndMerge();
        }

        static void performCopy(ZipArchiveEntry entry, string alternativeName = null, bool dryRun = false)
        {
            string exePath = Environment.ProcessPath ?? AppContext.BaseDirectory;
            var entryFullName = alternativeName ?? entry.FullName;
            string entryFullPath = FilesValidator.CheckPathTraversal(entryFullName, Path.GetDirectoryName(exePath));

            if (dryRun)
            {
                Console.WriteLine("[DRY-RUN] Would save " + entryFullName);
                return;
            }

            using (var e = entry.Open())
            {
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
                            e.CopyTo(tempFileStream);
                            tempFileStream.Close();
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
                    e.CopyTo(fileStream);
                    fileStream.Close();
                }
            }
        }

        private static void DisplayHelp()
        {
            Console.WriteLine("switch:");
            Console.WriteLine("  --help              : display this message");
            Console.WriteLine("");
            Console.WriteLine("  --api-url http://xx : use an alternative url for checking for updates");
            Console.WriteLine("  --force-download    : download the latest release even if it is not the most recent. Useful for tests");
            Console.WriteLine("  --use-preview       : download preview release if it is the most recent");
            Console.WriteLine("  --dry-run           : preview changes without modifying files");
            Console.WriteLine("  --wait-for-days  30 : ensure the releases has been made public for at least X days");
        }
    }
}
