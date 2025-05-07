using PingCastle.Healthcheck;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace PingCastle.Report
{
    public class ReportBenchmark
    {
        public static string GetDestination()
        {
#if TEST_BENCHMARK
            return "https://localhost:5001/Benchmark";
#else
            return "https://stat.pingcastle.com/Benchmark"; 
#endif
        }

        public static Dictionary<string, string> GetData(HealthcheckData report, ADHealthCheckingLicense license, bool shareStat = false)
        {
            var json = BuildStatJson(report, license, true);
            return new Dictionary<string, string>()
            {
                { "license", license.LicenseKey},
                { "json", json},
                { "signature", SignatureStatJson(license, json)},
            };
        }

        static string SignatureStatJson(ADHealthCheckingLicense license, string json)
        {
            byte[] key;
            using (SHA256 hashstring = SHA256.Create())
            {
                key = hashstring.ComputeHash(Encoding.UTF8.GetBytes(license.LicenseKey));
            }
            var hmac = new HMACSHA256(key);
            var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(json));
            return Convert.ToBase64String(hash);
        }
        static string BuildStatJson(HealthcheckData Report, ADHealthCheckingLicense license, bool shareStat)
        {
            var sb = new StringBuilder();
            sb.Append("{");
            sb.Append("\"generation\":\"");
            sb.Append(Report.GenerationDate.ToString("u"));
            sb.Append("\"");
            sb.Append(",\"version\":\"");
            sb.Append(Report.version.ToString());
            sb.Append("\"");
            sb.Append(",\"users\":");
            sb.Append(Report.UserAccountData.NumberActive);
            sb.Append(",\"computers\":");
            sb.Append(Report.ComputerAccountData.NumberActive);
            sb.Append(",\"score\":");
            sb.Append(Report.GlobalScore);
            sb.Append(",\"anomaly\":");
            sb.Append(Report.AnomalyScore);
            sb.Append(",\"staledobjects\":");
            sb.Append(Report.StaleObjectsScore);
            sb.Append(",\"trust\":");
            sb.Append(Report.TrustScore);
            sb.Append(",\"privilegedGroup\":");
            sb.Append(Report.PrivilegiedGroupScore);
            sb.Append(",\"maturityLevel\":");
            sb.Append(Report.MaturityLevel);
            sb.Append(",\"rules\":\"");
            if (Report.RiskRules != null)
            {
                bool first = true;
                foreach (var rule in Report.RiskRules)
                {
                    if (!first)
                        sb.Append(",");
                    sb.Append(rule.RiskId);
                    first = false;
                }
            }
            sb.Append("\"");

            if (license.IsBasic() || shareStat)
            {
                sb.Append(",\"id\":\"");
                using (SHA256 hashstring = SHA256.Create())
                {
                    sb.Append(Convert.ToBase64String(hashstring.ComputeHash(Encoding.UTF8.GetBytes(Report.DomainFQDN.ToLowerInvariant() + Report.DomainSid.ToUpperInvariant()))));
                }
                sb.Append("\"");
            }
            sb.Append("}");
            return sb.ToString();
        }
    }
}
