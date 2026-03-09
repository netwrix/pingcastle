namespace PingCastleCommon.Healthcheck
{
    using PingCastle.ADWS;
    using PingCastle.Data;
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using PingCastle.Healthcheck;

    /// <summary>
    /// Platform-agnostic implementation of account data processor.
    /// Contains AD account processing logic that works across different directory services.
    /// </summary>
    public class AccountDataProcessor : IAccountDataProcessor
    {
        public bool ProcessAccount(IAddAccountData data, ADItem x, bool computerCheck,
            DateTime dcWin2008Install, List<HealthcheckAccountDetailData> honeyPot = null)
        {
            return DoProcessAccountData(data, x, computerCheck, dcWin2008Install, honeyPot);
        }

        // See https://learn.microsoft.com/en-us/windows/win32/adschema/a-useraccountcontrol
        private bool DoProcessAccountData(IAddAccountData data, ADItem x, bool computerCheck, DateTime dcWin2008Install, List<HealthcheckAccountDetailData> listHoneyPot = null)
        {
            if (IsHoneyPotAccount(x, listHoneyPot))
                return false;

            // TODO: place to refactoring
            // Count of all accounts.
            data.AddWithoutDetail(null);

            ProcessAccountDuplicates(x, data);

            var isAccessDenied = x.UserAccountControl == 0;
            if (isAccessDenied)
            {
                data.AddWithoutDetail("AccessDenied");
                Trace.TraceError($"Access denied to get user data: {x.DistinguishedName}");
                return false;
            }

            ProcessAccountControlFlags(x, data);
            ProcessSIDHistory(x, data);
            ProcessPrimaryGroup(x, data, computerCheck);
            ProcessNotAesEnabled(x, data, dcWin2008Install);

            return true;
        }

        private void ProcessAccountDuplicates(ADItem x, IAddAccountData data)
        {
            if (x.DistinguishedName.Contains("cnf:"))
            {
                data.AddDetail("Duplicate", GetAccountDetail(x));
            }
            else if (!string.IsNullOrEmpty(x.SAMAccountName) && x.SAMAccountName.StartsWith("$duplicate-", StringComparison.InvariantCultureIgnoreCase))
            {
                data.AddDetail("Duplicate", GetAccountDetail(x));
            }
        }

        private bool IsHoneyPotAccount(ADItem x, List<HealthcheckAccountDetailData> listHoneyPot)
        {
            if (listHoneyPot == null)
            {
                return false;
            }

            foreach (var h in listHoneyPot)
            {
                if (string.Equals(h.Name, x.SAMAccountName, StringComparison.InvariantCultureIgnoreCase)
                    || string.Equals(h.DistinguishedName, x.DistinguishedName, StringComparison.InvariantCultureIgnoreCase))
                {
                    // ignore the account
                    h.Name = x.SAMAccountName;
                    h.CreationDate = x.WhenCreated;
                    h.DistinguishedName = x.DistinguishedName;
                    h.LastLogonDate = x.LastLogonTimestamp;
                    return true;
                }
            }

            return false;
        }

        private void ProcessNotAesEnabled(ADItem x, IAddAccountData data, DateTime dcWin2008Install)
        {
            if (dcWin2008Install != default(DateTime))
            {
                if ((x.PwdLastSet > new DateTime(1900, 1, 1) && dcWin2008Install > x.PwdLastSet) || (x.PwdLastSet <= new DateTime(1900, 1, 1) && x.WhenCreated.AddHours(1) < dcWin2008Install))
                {
                    data.AddDetail("NotAesEnabled", GetAccountDetail(x));
                }
                else if (x.ServicePrincipalName != null && x.ServicePrincipalName.Length > 0 && !string.IsNullOrEmpty(x.ServicePrincipalName[0]))
                {
                    // quote: "Users accounts, Group Managed Service accounts, and other accounts in Active Directory do not have the msds-SupportedEncryptionTypes value set automatically. "
                    // https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d#registrykey5021131
                    {
                        if ((x.msDSSupportedEncryptionTypes & (8 + 16)) == 0)
                        {
                            data.AddDetail("NotAesEnabled", GetAccountDetail(x));
                        }
                    }
                }
            }
        }

        private void ProcessPrimaryGroup(ADItem x, IAddAccountData data, bool computerCheck)
        {
            // check for bad primary group
            if (!computerCheck)
            {
                // Skip disabled accounts - they pose no active security risk
                if (x.IsAccountDisabled())
                    return;

                // not domain users & guest or the guest account
                if (x.PrimaryGroupID != 513 && x.PrimaryGroupID != 514 && x.ObjectSid != null && !x.ObjectSid.IsWellKnown(System.Security.Principal.WellKnownSidType.AccountGuestSid)
                    && !(x.PrimaryGroupID == 515 && (string.Equals(x.Class, "msDS-GroupManagedServiceAccount", StringComparison.OrdinalIgnoreCase) || string.Equals(x.Class, "msDS-ManagedServiceAccount", StringComparison.OrdinalIgnoreCase))))
                {
                    data.AddDetail("BadPrimaryGroup", GetAccountDetail(x));
                }
            }
            else
            {
                // Skip disabled computers - they pose no active security risk
                if (x.IsAccountDisabled())
                    return;

                var isDomainCompsAndGuests = x.PrimaryGroupID == 515 || x.PrimaryGroupID == 514;
                var isDCGroup = (x.PrimaryGroupID == 516 || x.PrimaryGroupID == 521) && x.DistinguishedName.Contains("OU=Domain Controllers,DC="); // 516 = RW DC, 521 = RO DC

                if (!isDomainCompsAndGuests && !isDCGroup)
                {
                    data.AddDetail("BadPrimaryGroup", GetAccountDetail(x));
                }
            }
        }

        public bool IsComputerActive(ADItem x)
        {
            return x.WhenCreated.AddMonths(6) > DateTime.Now ||
                   x.LastLogonTimestamp.AddMonths(6) > DateTime.Now ||
                   x.PwdLastSet.AddMonths(6) > DateTime.Now;
        }

        private void ProcessAccountControlFlags(ADItem x, IAddAccountData data)
        {
            if (x.IsAccountDisabled())
            {
                data.AddWithoutDetail("Disabled");

                if (x.IsTrustedForDelegation())
                {
                    // The detail name is "DisabledTrustedToAuthenticateForDelegation", but it checks for the correct flag "TRUSTED_FOR_DELEGATION".
                    // Used in risk "P-UnconstrainedDelegation"
                    data.AddDetail("DisabledTrustedToAuthenticateForDelegation", GetAccountDetail(x));
                }
            }
            else
            {
                data.AddWithoutDetail("Enabled");

                if (IsComputerActive(x))
                {
                    data.AddWithoutDetail("Active");
                }
                else
                {
                    data.AddDetail("Inactive", GetAccountDetail(x));
                }
                if (x.DoesNotRequireKerberosPreauthentication())
                {
                    data.AddDetail("NoPreAuth", GetAccountDetail(x));
                }
                if (x.IsAccountLockedOut())
                {
                    data.AddDetail("Locked", GetAccountDetail(x));
                }
                if (x.IsPasswordNeverExpires())
                {
                    // see https://techcommunity.microsoft.com/t5/exchange-team-blog/exchange-2013-2016-monitoring-mailboxes/ba-p/611004?msclkid=bd3898eeb18f11ecb0ad418f45f9d755
                    // exception for exchange accounts whose password is changed regularly
                    if (x.SAMAccountName != null && x.SAMAccountName.StartsWith("HealthMailbox", StringComparison.OrdinalIgnoreCase) && x.PwdLastSet.AddDays(40) > DateTime.Now)
                    {

                    }
                    else
                    {
                        data.AddDetail("PwdNeverExpires", GetAccountDetail(x));
                    }
                }
                if (x.IsPasswordNotRequired())
                {
                    // avoid to alert about exchange mailboxes
                    if (!x.DistinguishedName.Contains(",CN=Monitoring Mailboxes,"))
                    {
                        data.AddDetail("PwdNotRequired", GetAccountDetail(x));
                    }
                }
                // see [MS-KILE] && https://learn.microsoft.com/en-us/archive/blogs/openspecification/windows-configurations-for-kerberos-supported-encryption-type
                // msDSSupportedEncryptionTypes =1 => DES-CBC-CRC ; 2 => DES-CBC-MD5
                // requires at least Windows 2008 / Vista
                if (x.UsesDesKeyOnly() || ((x.msDSSupportedEncryptionTypes & (1 | 2)) > 0))
                {
                    data.AddDetail("DesEnabled", GetAccountDetail(x));
                }
                if (x.IsTrustedForDelegation())
                {
                    // The detail name is "EnabledTrustedToAuthenticateForDelegation", but it checks for the correct flag "TRUSTED_FOR_DELEGATION".
                    // If TRUSTED_TO_AUTH_FOR_DELEGATION (0x1000000) is needed for the constrained delegation -
                    // it should probably be added with a different name to preserve backwards compatibility.
                    // Used in risk "P-UnconstrainedDelegation"
                    data.AddDetail("EnabledTrustedToAuthenticateForDelegation", GetAccountDetail(x));
                }
                if (x.IsNormalAccount())
                {
                    data.AddDetail("ReversibleEncryption", GetAccountDetail(x));
                }
            }
        }

        public void ProcessSIDHistory(ADItem x, IAddAccountData data)
        {
            if (x.SIDHistory != null && x.SIDHistory.Length > 0)
            {
                data.AddSIDHistoryDetail(GetAccountDetail(x), x);
            }
        }

        public HealthcheckAccountDetailData GetAccountDetail(ADItem x)
        {
            HealthcheckAccountDetailData data = new HealthcheckAccountDetailData();
            data.DistinguishedName = x.DistinguishedName;
            data.Name = x.SAMAccountName;
            data.CreationDate = x.WhenCreated;
            data.LastLogonDate = x.LastLogonTimestamp;
            data.PwdLastSet = x.PwdLastSet;
            return data;
        }
    }
}
