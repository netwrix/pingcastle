using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.Management.Infrastructure;
using Microsoft.Management.Infrastructure.Options;
using PingCastle.UserInterface;
using PingCastleCommon.Utility;

namespace PingCastle.misc
{
    internal class CimHotfixHelper : IHotfixService
    {
        private static readonly Regex KbRegex = new Regex(@"KB(\d+)", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly TimeSpan OperationTimeout = TimeSpan.FromSeconds(90);
        private static readonly DateTime Ms17010AlertDate = new DateTime(2017, 3, 14, 0, 0, 0, DateTimeKind.Utc);

        public CimHotfixHelper()
        {
        }

        /// <summary>
        /// Retrieves installed hotfixes from a remote computer using CIM (WS-Man, then DCOM fallback).
        /// </summary>
        /// <param name="hostName">Target computer hostname or IP address</param>
        /// <param name="ui">User interface for displaying messages</param>
        /// <returns>A <see cref="HotfixQueryResult"/> containing discovered KB numbers and query status</returns>
        public HotfixQueryResult TryGetInstalledHotfixes(string hostName, IUserInterface ui, CancellationToken cancellationToken = default)
        {
            var result = QueryWithWsMan(hostName, ui, cancellationToken);
            if (result.Status == HotfixQueryStatus.Success)
            {
                return result;
            }

            Trace.WriteLine($"WS-Man failed for {hostName.SanitizeForLog()}, falling back to DCOM");
            return QueryWithDCom(hostName, ui, cancellationToken);
        }

        private HotfixQueryResult QueryWithWsMan(string hostName, IUserInterface ui, CancellationToken cancellationToken = default)
        {
            var sessionOptions = new WSManSessionOptions();
            sessionOptions.Timeout = OperationTimeout;
            return QueryHotfixes(hostName, sessionOptions, "WS-Man", ui, cancellationToken);
        }

        private HotfixQueryResult QueryWithDCom(string hostName, IUserInterface ui, CancellationToken cancellationToken = default)
        {
            var sessionOptions = new DComSessionOptions();
            sessionOptions.Timeout = OperationTimeout;
            return QueryHotfixes(hostName, sessionOptions, "DCOM", ui, cancellationToken);
        }

        private HotfixQueryResult QueryHotfixes(string hostName, CimSessionOptions sessionOptions, string protocol, IUserInterface ui, CancellationToken cancellationToken = default)
        {
            var result = new HotfixQueryResult();

            try
            {
                using (var session = CimSession.Create(hostName, sessionOptions))
                {
                    var operationOptions = new CimOperationOptions { CancellationToken = cancellationToken };
                    var instances = session.EnumerateInstances(@"root\cimv2", "Win32_QuickFixEngineering", operationOptions);
                    foreach (var instance in instances)
                    {
                        using (instance)
                        {
                            try
                            {
                                var hotfixId = instance.CimInstanceProperties["HotFixID"]?.Value?.ToString();
                                if (!string.IsNullOrEmpty(hotfixId))
                                {
                                    ExtractKbFromString(hotfixId, result.KbNumbers);
                                }

                                var description = instance.CimInstanceProperties["Description"]?.Value?.ToString();
                                if (!string.IsNullOrEmpty(description))
                                {
                                    ExtractKbFromString(description, result.KbNumbers);
                                }

                                if (result.MostRecentQualityUpdateDate == null)
                                {
                                    CheckPostAlertQualityUpdate(instance, result, Ms17010AlertDate);
                                }
                            }
                            catch (Exception ex)
                            {
                                Trace.WriteLine($"Error processing CIM QuickFix entry on {hostName.SanitizeForLog()} via {protocol}: {ex.Message}");
                            }
                        }
                    }
                }

                if (result.KbNumbers.Count > 0)
                {
                    result.Status = HotfixQueryStatus.Success;
                    Trace.WriteLine($"Retrieved {result.KbNumbers.Count} hotfixes from {hostName.SanitizeForLog()} using CIM ({protocol})");
                }
                else
                {
                    result.Status = HotfixQueryStatus.NoResults;
                    Trace.WriteLine($"No hotfixes found on {hostName.SanitizeForLog()} using CIM ({protocol})");
                }

                return result;
            }
            catch (CimException ex) when (ex.NativeErrorCode == NativeErrorCode.AccessDenied)
            {
                result.Status = HotfixQueryStatus.AccessDenied;
                result.FailureReason = ex.Message;
                var msg = $"Access denied querying hotfixes on {hostName.SanitizeForLog()} via CIM ({protocol}): {ex.Message}";
                Trace.WriteLine(msg);
                ui.DisplayMessage(msg);
                return result;
            }
            catch (CimException ex) when (
                ex.NativeErrorCode == NativeErrorCode.ServerLimitsExceeded ||
                ex.NativeErrorCode == NativeErrorCode.InvalidOperationTimeout)
            {
                result.Status = HotfixQueryStatus.Timeout;
                result.FailureReason = ex.Message;
                Trace.WriteLine($"Timeout querying hotfixes on {hostName.SanitizeForLog()} via CIM ({protocol}): {ex.Message}");
                return result;
            }
            catch (CimException ex)
            {
                result.Status = HotfixQueryStatus.ConnectionFailed;
                result.FailureReason = ex.Message;
                Trace.WriteLine($"CIM error querying hotfixes on {hostName.SanitizeForLog()} via {protocol}: {ex.Message}");
                return result;
            }
            catch (TimeoutException ex)
            {
                result.Status = HotfixQueryStatus.Timeout;
                result.FailureReason = ex.Message;
                Trace.WriteLine($"Timeout querying hotfixes on {hostName.SanitizeForLog()} via CIM ({protocol}): {ex.Message}");
                return result;
            }
            catch (Exception ex)
            {
                result.Status = HotfixQueryStatus.ConnectionFailed;
                result.FailureReason = ex.Message;
                Trace.WriteLine($"Error querying hotfixes on {hostName.SanitizeForLog()} via CIM ({protocol}): {ex.Message}");
                return result;
            }
        }

        private static void CheckPostAlertQualityUpdate(CimInstance instance, HotfixQueryResult result, DateTime alertCutoff)
        {
            var description = instance.CimInstanceProperties["Description"]?.Value?.ToString();
            if (!string.Equals(description, "Update", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            var installedOnStr = instance.CimInstanceProperties["InstalledOn"]?.Value?.ToString();
            if (string.IsNullOrEmpty(installedOnStr))
            {
                return;
            }

            if (DateTime.TryParse(installedOnStr, out var installedOn) && installedOn > alertCutoff)
            {
                result.MostRecentQualityUpdateDate = installedOn;
            }
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
