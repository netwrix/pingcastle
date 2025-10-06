using System.Collections.Generic;
using System.Net;

namespace PingCastle.Data
{

    public class PingCastleAnalyzerParameters
    {
        public bool IsPrivilegedMode { get; set; }
        public string Server { get; set; }
        public int Port { get; set; }
        public NetworkCredential Credential { get; set; }
        public bool PerformExtendedTrustDiscovery { get; set; }
        public List<string> AdditionalNamesForDelegationAnalysis { get; set; }
    }

    public interface IPingCastleAnalyzer<T> where T : IPingCastleReport
    {
        T PerformAnalyze(PingCastleAnalyzerParameters parameters);
    }
}
