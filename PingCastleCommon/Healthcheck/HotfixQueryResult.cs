using System;
using System.Collections.Generic;

namespace PingCastle.misc
{
    public enum HotfixQueryStatus
    {
        NotTested,
        Success,
        ConnectionFailed,
        AccessDenied,
        Timeout,
        NoResults
    }

    public class HotfixQueryResult
    {
        public HotfixQueryStatus Status { get; set; } = HotfixQueryStatus.NotTested;

        public HashSet<string> KbNumbers { get; set; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        public DateTime? MostRecentQualityUpdateDate { get; set; }

        public string FailureReason { get; set; }
    }
}
