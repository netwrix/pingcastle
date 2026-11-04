using System;
using System.Text.RegularExpressions;
using PingCastle.ADWS;

namespace PingCastle.Healthcheck
{
    internal static class RemoteGPOHelper
    {
        private static readonly Regex GpoDnRegex = new Regex(
            @"^CN=\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\},CN=Policies,CN=System,DC=",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

        public static string GetDomainDN(string dn)
        {
            if (string.IsNullOrEmpty(dn))
            {
                return null;
            }

            if (dn.StartsWith("DC=", StringComparison.OrdinalIgnoreCase))
            {
                return dn;
            }

            int index = dn.IndexOf(",DC=", StringComparison.OrdinalIgnoreCase);
            return index < 0 ? null : dn.Substring(index + 1);
        }

        public static string DomainDNToFqdn(string domainDN)
        {
            if (string.IsNullOrEmpty(domainDN))
            {
                return null;
            }

            return Regex.Replace(domainDN, "(,)?DC=", m => m.Groups[1].Success ? "." : string.Empty, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant).ToLowerInvariant();
        }

        public static bool IsRemoteGPODN(string dn, ADDomainInfo local)
        {
            if (string.IsNullOrEmpty(dn) || !GpoDnRegex.IsMatch(dn))
            {
                return false;
            }

            string domainDN = GetDomainDN(dn);
            return domainDN != null && !string.Equals(domainDN, local.DefaultNamingContext, StringComparison.OrdinalIgnoreCase);
        }

        public static string GetRemoteGPOId(string guid, string fqdn)
        {
            return (guid + "@" + fqdn).ToLowerInvariant();
        }
    }
}
