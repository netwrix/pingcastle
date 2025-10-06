using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security.AccessControl;
using System.Security.Principal;
using PingCastle.ADWS;
using PingCastle.misc;

namespace PingCastle.Healthcheck
{
    internal static class HealthCheckCertificateAuthorityDataExtensions
    {
        internal static bool TryGetServerSecurityFromRegistry(this HealthCheckCertificateAuthorityData ca, out ActiveDirectorySecurity securityDescriptor)
        {
            securityDescriptor = null;

            if (ca.DnsHostName == null) throw new ArgumentException("DnsHostname is null");
            if (ca.Name == null) throw new ArgumentException("Name is null");

            var keyPath = $"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{ca.Name}";
            if (!RegistryHelper.TryGetHKLMKeyBinaryValue(keyPath, "Security", ca.DnsHostName, out var security))
                return false;

            securityDescriptor = new ActiveDirectorySecurity();
            securityDescriptor.SetSecurityDescriptorBinaryForm(security, AccessControlSections.All);

            return true;
        }

        internal static bool TryGetEnrollmentRights(this HealthCheckCertificateAuthorityData ca, out RawSecurityDescriptor securityDescriptor)
        {
            securityDescriptor = null;

            if (ca.DnsHostName == null) throw new ArgumentException("DnsHostname is null");
            if (ca.Name == null) throw new ArgumentException("Name is null");

            var keyPath = $"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{ca.Name}";
            if (!RegistryHelper.TryGetHKLMKeyBinaryValue(keyPath, "EnrollmentAgentRights", ca.DnsHostName, out var security))
                return false;

            securityDescriptor = new RawSecurityDescriptor(security, 0);

            return true;
        }
    }

    internal static class PrincipalExtensions
    {
        internal static string GetName(this SecurityIdentifier sid)
        {
            return ((NTAccount)sid.Translate(typeof(NTAccount))).Value;
        }

        internal static string GetNameFromSid(this string sidString)
        {
            try
            {
                var sid = new SecurityIdentifier(sidString);
                return sid.GetName();
            }
            catch
            {
                return sidString;
            }
        }
    }

    public static class ReplPropertyMetaDataExtensions
    {
        public static bool IsLapsFound(this Dictionary<int, ADItem.ReplPropertyMetaDataItem> replPropertyMetaData, int lapsId)
        {
            return lapsId != 0 && replPropertyMetaData != null && replPropertyMetaData.ContainsKey(lapsId);
        }

        public static bool IsLapsFound(this Dictionary<int, ADItem.ReplPropertyMetaDataItem> replPropertyMetaData, int lapsId, out DateTime lastOriginatingChange)
        {
            var isLapsFound = replPropertyMetaData.IsLapsFound(lapsId);
            lastOriginatingChange = isLapsFound ? replPropertyMetaData[lapsId].LastOriginatingChange : DateTime.MinValue;

            return isLapsFound;
        }
    }
}
