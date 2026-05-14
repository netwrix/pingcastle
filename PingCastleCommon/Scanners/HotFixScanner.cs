namespace PingCastle.Scanners
{
    using PingCastle.ADWS;
    using PingCastle.Healthcheck;
    using PingCastle.misc;
    using PingCastleCommon.Utility;
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Threading;

    /// <summary>
    /// Base class for scanners that need to retrieve and analyse installed hotfixes.
    /// Provides common functionality for hotfix retrieval.
    /// </summary>
    abstract public class HotFixScanner : ScannerBase
    {
        protected readonly IHotFixCollector HotfixCollector;
        protected readonly IOperatingSystemInfoProvider OsInfoProvider;

        protected HotFixScanner(IHotFixCollector hotfixCollector, IOperatingSystemInfoProvider osInfoProvider, IIdentityProvider identityProvider)
            : base(identityProvider)
        {
            HotfixCollector = hotfixCollector ?? throw new ArgumentNullException(nameof(hotfixCollector));
            OsInfoProvider = osInfoProvider ?? throw new ArgumentNullException(nameof(osInfoProvider));
        }

        /// <summary>
        /// Retrieves installed hotfixes for a computer.
        /// </summary>
        /// <param name="computerName">The name of the computer to scan.</param>
        /// <param name="cancellationToken">Token used to cancel the operation if the per-host deadline fires.</param>
        /// <returns>A <see cref="HotfixQueryResult"/> containing query status and discovered KB numbers</returns>
        protected HotfixQueryResult RetrieveInstalledHotfixes(string computerName, CancellationToken cancellationToken = default)
        {
            try
            {
                return HotfixCollector.GetInstalledHotfixes(computerName, cancellationToken: cancellationToken);
            }
            catch (Exception ex)
            {
                Trace.WriteLine($"Error retrieving hotfixes for {computerName.SanitizeForLog()}: {ex.Message}");
                return new HotfixQueryResult { Status = HotfixQueryStatus.ConnectionFailed, FailureReason = ex.Message };
            }
        }

        /// <summary>
        /// Retrieves the operating system information for a domain controller.
        /// </summary>
        /// <param name="computerName">The computer/domain controller name</param>
        /// <returns>The operating system name (e.g. "Windows Server 2025"), or "Unknown" if retrieval fails</returns>
        protected string RetrieveOperatingSystem(string computerName)
        {
            try
            {
                string osName = OsInfoProvider.GetOperatingSystemName(computerName);
                if (!string.IsNullOrEmpty(osName))
                {
                    Trace.WriteLine($"Retrieved OS name for {computerName}: {osName}");
                    return osName;
                }

                Trace.WriteLine($"Unable to retrieve OS information for {computerName}");
                return "Unknown";
            }
            catch (Exception ex)
            {
                Trace.WriteLine($"Error retrieving OS for {computerName}: {ex.Message}");
                return "Unknown";
            }
        }
    }
}
