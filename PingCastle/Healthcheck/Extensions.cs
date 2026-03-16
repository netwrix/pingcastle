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

        /// <summary>
        /// Reads InterfaceFlags DWORD from the CA configuration registry key.
        /// Bit 0x200 = IF_ENFORCEENCRYPTICERTREQUEST (ESC11).
        /// When this flag is NOT set the ICertRequest DCOM interface accepts
        /// unauthenticated/cleartext requests, enabling NTLM relay attacks.
        /// </summary>
        internal static bool TryGetInterfaceFlags(this HealthCheckCertificateAuthorityData ca, out int interfaceFlags)
        {
            interfaceFlags = 0;

            if (ca.DnsHostName == null) throw new ArgumentException("DnsHostname is null");
            if (ca.Name == null) throw new ArgumentException("Name is null");

            var keyPath = $"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{ca.Name}";
            return RegistryHelper.TryGetHKLMKeyDWordValue(keyPath, "InterfaceFlags", ca.DnsHostName, out interfaceFlags);
        }

        /// <summary>
        /// Reads AuditFilter DWORD from the CA configuration registry key.
        /// A value of 0 means no certificate lifecycle events are audited on this CA —
        /// issuance, revocation, and key archival operations are not logged.
        /// Recommended value: 127 (all events, MS baseline) or at minimum 0x7F.
        /// </summary>
        internal static bool TryGetAuditFilter(this HealthCheckCertificateAuthorityData ca, out int auditFilter)
        {
            auditFilter = 0;

            if (ca.DnsHostName == null) throw new ArgumentException("DnsHostname is null");
            if (ca.Name == null) throw new ArgumentException("Name is null");

            var keyPath = $"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{ca.Name}";
            return RegistryHelper.TryGetHKLMKeyDWordValue(keyPath, "AuditFilter", ca.DnsHostName, out auditFilter);
        }

        /// <summary>
        /// Reads the EditFlags DWORD from the CA policy module registry key.
        /// Bit 0x40 = EDITF_ATTRIBUTESUBJECTALTNAME2 (ESC6).
        /// </summary>
        internal static bool TryGetEditFlags(this HealthCheckCertificateAuthorityData ca, out int editFlags)
        {
            editFlags = 0;

            if (ca.DnsHostName == null) throw new ArgumentException("DnsHostname is null");
            if (ca.Name == null) throw new ArgumentException("Name is null");

            var keyPath = $"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{ca.Name}\\PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy";
            return RegistryHelper.TryGetHKLMKeyDWordValue(keyPath, "EditFlags", ca.DnsHostName, out editFlags);
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
