using System.Diagnostics;
using System.Threading;
using PingCastle.misc;
using PingCastle.UserInterface;
using PingCastleCommon.Utility;

namespace PingCastle.Healthcheck
{
    public class HotFixCollector : IHotFixCollector
    {
        private readonly IHotfixService _hotfixService;

        public HotFixCollector(IHotfixService hotfixService)
        {
            _hotfixService = hotfixService ?? throw new System.ArgumentNullException(nameof(hotfixService));
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

            var result = _hotfixService.TryGetInstalledHotfixes(hostName, ui, cancellationToken);
            if (result.Status == HotfixQueryStatus.Success)
            {
                Trace.WriteLine($"Retrieved {result.KbNumbers.Count} hotfixes from {hostName.SanitizeForLog()}");
            }
            else
            {
                Trace.WriteLine($"Hotfix detection failed for {hostName.SanitizeForLog()} with status {result.Status}: {result.FailureReason}");
            }

            return result;
        }
    }
}
