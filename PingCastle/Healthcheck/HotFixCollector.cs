using System.Diagnostics;
using System.Threading;
using PingCastle.misc;
using PingCastle.UserInterface;
using PingCastleCommon.Utility;

namespace PingCastle.Healthcheck
{
    public class HotFixCollector : IHotFixCollector
    {
        private readonly IHotfixService _cimService;
        private readonly IHotfixService _wmiService;

        public HotFixCollector(IHotfixService cimService, IHotfixService wmiService)
        {
            _cimService = cimService ?? throw new System.ArgumentNullException(nameof(cimService));
            _wmiService = wmiService ?? throw new System.ArgumentNullException(nameof(wmiService));
        }

        public HotfixQueryResult GetInstalledHotfixes(string hostName, bool isPrivilegedMode = true, CancellationToken cancellationToken = default)
        {
            if (!isPrivilegedMode)
            {
                Trace.WriteLine($"Hotfix collection skipped for {hostName.SanitizeForLog()} - not in privileged mode");
                return new HotfixQueryResult { Status = HotfixQueryStatus.NotTested, FailureReason = "Not in privileged mode" };
            }

            var ui = UserInterfaceFactory.GetUserInterface();

            if (!NetworkHelper.IsValidHostName(hostName))
            {
                var errorMsg = $"Invalid hostname '{hostName.SanitizeForLog()}' - contains potentially malicious characters or exceeds length limits";
                Trace.WriteLine(errorMsg);
                ui.DisplayMessage(errorMsg);
                return new HotfixQueryResult { Status = HotfixQueryStatus.ConnectionFailed, FailureReason = "Invalid hostname" };
            }

            var cimResult = _cimService.TryGetInstalledHotfixes(hostName, ui, cancellationToken);
            if (cimResult.Status == HotfixQueryStatus.Success)
            {
                Trace.WriteLine($"CIM succeeded for {hostName.SanitizeForLog()} with {cimResult.KbNumbers.Count} hotfixes");
                return cimResult;
            }

            Trace.WriteLine($"CIM failed for {hostName.SanitizeForLog()} with status {cimResult.Status}: {cimResult.FailureReason}");

            if (cimResult.Status == HotfixQueryStatus.AccessDenied)
            {
                Trace.WriteLine($"Skipping WMI fallback for {hostName.SanitizeForLog()} - same credentials would fail");
                return cimResult;
            }

            if (cimResult.Status == HotfixQueryStatus.ConnectionFailed || cimResult.Status == HotfixQueryStatus.Timeout || cimResult.Status == HotfixQueryStatus.NoResults)
            {
                Trace.WriteLine($"Attempting WMI fallback for {hostName.SanitizeForLog()}");
                var wmiResult = _wmiService.TryGetInstalledHotfixes(hostName, ui, cancellationToken);
                if (wmiResult.Status == HotfixQueryStatus.Success)
                {
                    Trace.WriteLine($"WMI fallback succeeded for {hostName.SanitizeForLog()} with {wmiResult.KbNumbers.Count} hotfixes");
                    return wmiResult;
                }

                Trace.WriteLine($"WMI fallback also failed for {hostName.SanitizeForLog()} with status {wmiResult.Status}: {wmiResult.FailureReason}");
                return wmiResult;
            }

            return cimResult;
        }
    }
}
