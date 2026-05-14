using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Management;
using System.Text.RegularExpressions;
using System.Threading;
using PingCastle.UserInterface;
using PingCastleCommon.Utility;

namespace PingCastle.misc
{
    internal class WmiHotfixHelper : IHotfixService
    {
        private static readonly Regex KbRegex = new Regex(@"KB(\d+)", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly DateTime Ms17010AlertDate = new DateTime(2017, 3, 14, 0, 0, 0, DateTimeKind.Utc);

        public WmiHotfixHelper()
        {
        }

        /// <summary>
        /// Retrieves installed hotfixes from a remote computer using WMI.
        /// </summary>
        /// <param name="hostName">Target computer hostname or IP address</param>
        /// <param name="ui">User interface for displaying messages</param>
        /// <returns>A <see cref="HotfixQueryResult"/> containing discovered KB numbers and query status</returns>
        public HotfixQueryResult TryGetInstalledHotfixes(string hostName, IUserInterface ui, CancellationToken cancellationToken = default)
        {
            var result = new HotfixQueryResult();

            try
            {
                if (TryGetHotfixesFromQuickFixEngineering(hostName, result, ui))
                {
                    if (result.KbNumbers.Count > 0)
                    {
                        result.Status = HotfixQueryStatus.Success;
                        Trace.WriteLine($"Retrieved {result.KbNumbers.Count} hotfixes from {hostName.SanitizeForLog()} using Win32_QuickFixEngineering");
                        return result;
                    }

                    Trace.WriteLine($"No hotfixes found on {hostName.SanitizeForLog()} using WMI methods");
                    result.Status = HotfixQueryStatus.NoResults;
                    return result;
                }

                Trace.WriteLine($"WMI connection failed for {hostName.SanitizeForLog()}");
                result.Status = HotfixQueryStatus.ConnectionFailed;
                result.FailureReason = "WMI query failed — see trace log for details";
                return result;
            }
            catch (UnauthorizedAccessException ex)
            {
                result.Status = HotfixQueryStatus.AccessDenied;
                result.FailureReason = ex.Message;
                var msg = $"Access denied retrieving hotfixes from {hostName.SanitizeForLog()} using WMI: {ex.Message}";
                Trace.WriteLine(msg);
                ui.DisplayMessage(msg);
                return result;
            }
            catch (System.Runtime.InteropServices.COMException ex) when (ex.HResult == unchecked((int)0x800706BA))
            {
                result.Status = HotfixQueryStatus.ConnectionFailed;
                result.FailureReason = ex.Message;
                Trace.WriteLine($"RPC server unavailable for {hostName.SanitizeForLog()}: {ex.Message}");
                return result;
            }
            catch (TimeoutException ex)
            {
                result.Status = HotfixQueryStatus.Timeout;
                result.FailureReason = ex.Message;
                Trace.WriteLine($"Timeout retrieving hotfixes from {hostName.SanitizeForLog()}: {ex.Message}");
                return result;
            }
            catch (Exception ex)
            {
                result.Status = HotfixQueryStatus.ConnectionFailed;
                result.FailureReason = ex.Message;
                var msg = $"Could not retrieve hotfixes from {hostName.SanitizeForLog()} using WMI methods: {ex.Message}";
                Trace.WriteLine(msg);
                ui.DisplayMessage(msg);
                return result;
            }
        }

        private bool TryGetHotfixesFromQuickFixEngineering(string hostName, HotfixQueryResult result, IUserInterface ui)
        {
            try
            {
                var connectionOptions = CreateConnectionOptions();
                var scope = new ManagementScope($"\\\\{hostName}\\root\\cimv2", connectionOptions);
                scope.Connect();

                var query = new ObjectQuery("SELECT HotFixID, Description, InstalledOn FROM Win32_QuickFixEngineering");
                using (var searcher = new ManagementObjectSearcher(scope, query))
                using (var collection = searcher.Get())
                {
                    foreach (ManagementObject obj in collection)
                    {
                        try
                        {
                            var hotfixId = obj["HotFixID"]?.ToString();
                            if (!string.IsNullOrEmpty(hotfixId))
                            {
                                ExtractKbFromString(hotfixId, result.KbNumbers);
                            }

                            var description = obj["Description"]?.ToString();
                            if (!string.IsNullOrEmpty(description))
                            {
                                ExtractKbFromString(description, result.KbNumbers);
                            }

                            if (result.MostRecentQualityUpdateDate == null)
                            {
                                CheckPostAlertQualityUpdate(obj, result, Ms17010AlertDate);
                            }
                        }
                        catch (Exception ex)
                        {
                            Trace.WriteLine($"Error processing QuickFix entry on {hostName.SanitizeForLog()}: {ex.Message}");
                        }
                        finally
                        {
                            obj?.Dispose();
                        }
                    }
                }

                return true;
            }
            catch (UnauthorizedAccessException ex)
            {
                var msg = $"Access denied when querying Win32_QuickFixEngineering on {hostName.SanitizeForLog()}: {ex.Message}";
                Trace.WriteLine(msg);
                ui.DisplayMessage(msg);
                return false;
            }
            catch (Exception ex)
            {
                Trace.WriteLine($"Error querying Win32_QuickFixEngineering on {hostName.SanitizeForLog()}: {ex.Message}");
                return false;
            }
        }

        private static void CheckPostAlertQualityUpdate(ManagementObject obj, HotfixQueryResult result, DateTime alertCutoff)
        {
            var description = obj["Description"]?.ToString();
            if (!string.Equals(description, "Update", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            var installedOnStr = obj["InstalledOn"]?.ToString();
            if (string.IsNullOrEmpty(installedOnStr))
            {
                return;
            }

            if (DateTime.TryParse(installedOnStr, out var installedOn) && installedOn > alertCutoff)
            {
                result.MostRecentQualityUpdateDate = installedOn;
            }
        }

        private ConnectionOptions CreateConnectionOptions()
        {
            var options = new ConnectionOptions
            {
                EnablePrivileges = true,
                Timeout = TimeSpan.FromSeconds(90),
                Authentication = AuthenticationLevel.PacketPrivacy,
                Impersonation = ImpersonationLevel.Impersonate
            };

            return options;
        }

        private void ExtractKbFromString(string input, HashSet<string> hotfixes)
        {
            if (string.IsNullOrEmpty(input))
                return;

            var matches = KbRegex.Matches(input);
            foreach (Match match in matches)
            {
                if (match.Success && match.Groups.Count > 1)
                {
                    var kbNumber = "KB" + match.Groups[1].Value;
                    hotfixes.Add(kbNumber);
                }
            }
        }
    }
}
