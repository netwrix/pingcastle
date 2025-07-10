//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Text;

namespace PingCastle.Rules
{
    [AttributeUsage(AttributeTargets.Class, Inherited = false)]
    public class RuleModelAttribute : Attribute
    {
        public RuleModelAttribute(string Id, RiskRuleCategory Category, RiskModelCategory Model)
        {
            this.Id = Id;
            this.Category = Category;
            this.Model = Model;
        }

        public string Id { get; private set; }
        public RiskRuleCategory Category { get; private set; }
        public RiskModelCategory Model { get; private set; }
    }

    [AttributeUsage(AttributeTargets.Class, Inherited = false)]
    public class RuleNotPartiallyRecomputableAttribute : Attribute
    {
        
    }

    public interface IRuleMaturity
    {
        int Level { get; }
    }

    [AttributeUsage(AttributeTargets.Class, Inherited = false)]
    public class RuleIntroducedInAttribute : Attribute
    {
        public RuleIntroducedInAttribute(int major, int minor, int build = 0, int revision = 0)
        {
            Major = major;
            Minor = minor;
            Build = build;
            Revision = revision;
        }

        public int Major { get; private set; }
        public int Minor { get; private set; }
        public int Build { get; private set; }
        public int Revision { get; private set; }

        private Version _version;
        public Version Version
        {
            get
            {
                if (_version == null)
                {
                    _version = new Version(Major, Minor, Build, Revision);
                }
                return _version;
            }
        }
    }

    public enum RuleComputationType
    {
        TriggerOnThreshold,
        TriggerOnPresence,
        PerDiscover,
        PerDiscoverWithAMinimumOf,
        TriggerIfLessThan,
    }

    [AttributeUsage(AttributeTargets.Class, Inherited = false, AllowMultiple = true)]
    public class RuleComputationAttribute : Attribute
    {
        public RuleComputationAttribute() { }

        public RuleComputationAttribute(RuleComputationType ComputationType, int Score, int Threshold = 0, int Order = 1)
        {
            this.ComputationType = ComputationType;
            this.Score = Score;
            this.Threshold = Threshold;
            this.Order = Order;
        }

        public RuleComputationType ComputationType { get; private set; }
        public int Score { get; private set; }
        public int Threshold { get; private set; }
        public int Order { get; private set; }

        public bool HasMatch(int value, ref int points)
        {
            switch (ComputationType)
            {
                case RuleComputationType.TriggerOnPresence:
                    if (value > 0)
                    {
                        points = Score;
                        return true;
                    }
                    return false;
                case RuleComputationType.PerDiscoverWithAMinimumOf:
                    if (value > 0)
                    {
                        points = value * Score;
                        if (points < Threshold)
                            points = Threshold;
                        return true;
                    }
                    return false;
                case RuleComputationType.PerDiscover:
                    if (value > 0)
                    {
                        points = value * Score;
                        return true;
                    }
                    return false;
                case RuleComputationType.TriggerOnThreshold:
                    if (value >= Threshold)
                    {
                        points = Score;
                        return true;
                    }
                    return false;
                case RuleComputationType.TriggerIfLessThan:
                    if (value < Threshold)
                    {
                        points = Score;
                        return true;
                    }
                    return false;
                default:
                    throw new NotImplementedException();
            }
        }

        public static string GetComputationModelString(IEnumerable<RuleComputationAttribute> RuleComputation)
        {
            StringBuilder sb = new StringBuilder();
            bool first = true;
            foreach(var rule in RuleComputation)
            {
                if (first)
                {
                    first = false;
                }
                else
                {
                    sb.Append("\r\nthen ");
                }
                switch (rule.ComputationType)
                {
                    case RuleComputationType.TriggerOnThreshold:
                        sb.Append(rule.Score);
                        sb.Append(" points if the occurence is greater than or equals than ");
                        sb.Append(rule.Threshold);
                        break;
                    case RuleComputationType.TriggerOnPresence:
                        if (rule.Score > 0)
                        {
                            sb.Append(rule.Score);
                            sb.Append(" points if present");
                        }
                        else
                        {
                            sb.Append("Informative rule (0 point)");
                        }
                        break;
                    case RuleComputationType.PerDiscover:
                        sb.Append(rule.Score);
                        sb.Append(" points per discovery");
                        break;
                    case RuleComputationType.PerDiscoverWithAMinimumOf:
                        sb.Append(rule.Score);
                        sb.Append(" points per discovery with a minimal of ");
                        sb.Append(rule.Threshold);
                        sb.Append(" points");
                        break;
                    case RuleComputationType.TriggerIfLessThan:
                        sb.Append(rule.Score);
                        sb.Append(" points if the occurence is strictly lower than ");
                        sb.Append(rule.Threshold);
                        break;
                }
            }
            return sb.ToString();
        }
    }

    public class RuleFrameworkReference : Attribute, IEquatable<RuleFrameworkReference>, IComparable<RuleFrameworkReference>
    {
        public virtual string URL
        {
            get; set;
        }
        public virtual string Label
        {
            get; set;
        }

        public virtual string Country { get; set; }

        public virtual int CompareTo(RuleFrameworkReference other)
        {
            return String.CompareOrdinal(Label, other.Label);
        }

        public virtual bool Equals(RuleFrameworkReference other)
        {
            return String.Equals(Label, other.Label) && String.Equals(URL, other.URL);
        }

        public virtual string GenerateLink()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("<a href=\"");
            sb.Append(URL);
            sb.Append("\">");
            if (!string.IsNullOrEmpty(Country))
            {
                sb.Append("[");
                sb.Append(Country.ToUpperInvariant());
                sb.Append("]");
            }
            sb.Append(Label);
            sb.Append("</a>");
            return sb.ToString();
        }
    }

    public enum STIGFramework
    {
        Domain,
        Forest,
        Windows7,
        Windows10,
        Windows2008,
        ActiveDirectoryService2003,
        ActiveDirectoryService2008
    }

    [AttributeUsage(AttributeTargets.Class, Inherited = false, AllowMultiple = true)]
    public class RuleSTIGAttribute : RuleFrameworkReference
    {
        public RuleSTIGAttribute(string id, string title = null, STIGFramework framework = STIGFramework.Domain)
        {
            ID = id;
            Framework = framework;
            Title = title;
            Country = "us";
        }

        public string ID { get; private set; }
        public STIGFramework Framework { get; private set; }
        public string Title { get; private set; }

        public override string URL
        {
            get
            {
                switch (Framework)
                {
                    case STIGFramework.Forest:
                        return "https://www.stigviewer.com/stig/active_directory_forest/2016-12-19/finding/" + ID;
                    case STIGFramework.Windows7:
                        return "https://www.stigviewer.com/stig/windows_7/2012-08-22/finding/" + ID;
                    case STIGFramework.Windows10:
                        return "https://www.stigviewer.com/stig/windows_10/2018-04-06/finding/" + ID;
                    case STIGFramework.Windows2008:
                        return "https://www.stigviewer.com/stig/windows_2008_member_server/2018-03-07/finding/" + ID;
                    case STIGFramework.ActiveDirectoryService2003:
                        return "https://www.stigviewer.com/stig/active_directory_service_2003/2011-05-20/finding/" + ID;
                    case STIGFramework.ActiveDirectoryService2008:
                        return "https://www.stigviewer.com/stig/active_directory_service_2008/2011-05-23/finding/" + ID;
                    default:
                        return "https://www.stigviewer.com/stig/active_directory_domain/2017-12-15/finding/" + ID;
                }
            }
        }

        public override string Label { get { return "STIG " + ID + (!String.IsNullOrEmpty(Title) ? " - " + Title : null); } }
    }

    [AttributeUsage(AttributeTargets.Class, Inherited = false, AllowMultiple = true)]
    public class RuleANSSIAttribute : RuleFrameworkReference
    {
        public RuleANSSIAttribute(string id, string location)
        {
            ID = id;
            Location = location;
            Country = "fr";
        }

        public string ID { get; private set; }
        public string Location { get; private set; }

        public override string URL
        {
            get
            {
                // old: https://www.ssi.gouv.fr/uploads/IMG/pdf/NP_ActiveDirectory_NoteTech.pdf
                // new: https://cyber.gouv.fr/sites/default/files/IMG/pdf/NP_ActiveDirectory_NoteTech.pdf
                return "https://cyber.gouv.fr/sites/default/files/IMG/pdf/NP_ActiveDirectory_NoteTech.pdf" + (!String.IsNullOrEmpty(Location) ? "#" + Location : null);
            }
        }

        public override string Label { get { return "ANSSI - Recommandations de sécurité relatives à Active Directory - " + ID + (!String.IsNullOrEmpty(Location) ? " [" + Location + "]" : null); } }
    }

    [AttributeUsage(AttributeTargets.Class, Inherited = false, AllowMultiple = true)]
    public class RuleCERTFRAttribute : RuleFrameworkReference
    {
        public RuleCERTFRAttribute(string id, string section = null)
        {
            ID = id;
            Section = section;
            Country = "fr";
        }

        public string ID { get; private set; }
        public string Section { get; private set; }
        public override string URL
        {
            get
            {
                string path = "https://www.cert.ssi.gouv.fr/actualite/";
                if (ID.Contains("-ALE-"))
                    path = "https://www.cert.ssi.gouv.fr/alerte/";
                if (ID.Contains("-INF-"))
                    path = "https://www.cert.ssi.gouv.fr/information/";
                return path + ID + (!String.IsNullOrEmpty(Section) ? "/#" + Section : null);
            }
        }

        public override string Label { get { return "ANSSI " + ID; } }
    }

    [AttributeUsage(AttributeTargets.Class, Inherited = false, AllowMultiple = true)]
    public class RuleDurANSSIAttribute : RuleFrameworkReference, IRuleMaturity
    {
        public RuleDurANSSIAttribute(int level, string id, string description)
        {
            ID = id;
            Level = level;
            Country = "fr";
            Label = "ANSSI - " + description + " (vuln" + level + "_" + id + ")";
            ANSSILabel = description;
        }

        public int Level { get; set; }
        public string ID { get; private set; }
        public string ANSSILabel { get; private set; }

        public override string URL
        {
            get
            {
                return "https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_" + ID;
            }
        }

        public override bool Equals(RuleFrameworkReference other)
        {
            if (other is RuleDurANSSIAttribute)
            {
                return String.Equals(Label, other.Label) && String.Equals(URL, other.URL) && Level == ((RuleDurANSSIAttribute)other).Level;
            }
            else
            {
                return base.Equals(other);
            }
        }

        public override string GenerateLink()
        {
            return base.GenerateLink() + "<span class=\"badge grade-" + Level + "\">" + Level + "</span>";
        }
    }

    [AttributeUsage(AttributeTargets.Class, Inherited = false, AllowMultiple = false)]
    public class RuleMaturityLevelAttribute : Attribute, IRuleMaturity
    {
        public RuleMaturityLevelAttribute(int Level)
        {
            this.Level = Level;
        }

        public int Level { get; set; }
    }

    public enum MitreAttackMainTechnique
    {
        [Description("Initial Access")]
        InitialAccess,
        [Description("Execution")]
        Execution,
        [Description("Privilege Escalation")]
        PrivilegeEscalation,
        [Description("Defense Evasion")]
        DefenseEvasion,
        [Description("Credential Access")]
        CredentialAccess,
        [Description("Discovery")]
        Discovery,
        [Description("Lateral Movement")]
        LateralMovement,
        [Description("Persistence")]
        Persistence,
    }

    public enum MitreAttackTechnique
    {
        [MitreAttackTechniqueAttribute(MitreAttackMainTechnique.InitialAccess, "T1078", "003", "Valid Accounts", "Local Accounts")]
        ValidAccountsLocalAccounts,
        [MitreAttackTechniqueAttribute(MitreAttackMainTechnique.PrivilegeEscalation, "T1134", "005", "Access Token Manipulation", "SID-History Injection")]
        AccessTokenManipulationSIDHistoryInjection,
        [MitreAttackTechniqueAttribute(MitreAttackMainTechnique.DefenseEvasion, "T1207", "Rogue Domain Controller")]
        RogueDomainController,
        [MitreAttackTechniqueAttribute(MitreAttackMainTechnique.DefenseEvasion, "T1600", "001", "Weaken Encryption", "Reduce Key Space")]
        WeakenEncryptionReduceKeySpace,
        [MitreAttackTechniqueAttribute(MitreAttackMainTechnique.CredentialAccess, "T1558", "Steal or Forge Kerberos Tickets")]
        StealorForgeKerberosTickets,
        [MitreAttackTechniqueAttribute(MitreAttackMainTechnique.CredentialAccess, "T1558", "001", "Steal or Forge Kerberos Tickets", "Golden Ticket")]
        StealorForgeKerberosTicketsGoldenTicket,
        [MitreAttackTechniqueAttribute(MitreAttackMainTechnique.CredentialAccess, "T1558", "003", "Steal or Forge Kerberos Tickets", "Kerberoasting")]
        StealorForgeKerberosTicketsKerberoasting,
        [MitreAttackTechniqueAttribute(MitreAttackMainTechnique.CredentialAccess, "T1558", "004", "Steal or Forge Kerberos Tickets", "AS-REP Roasting")]
        StealorForgeKerberosTicketsASREPRoasting,
        [MitreAttackTechniqueAttribute(MitreAttackMainTechnique.CredentialAccess, "T1555", "005", "Credentials from Password Stores", "Password Managers")]
        CredentialsfromPasswordStoresPasswordManagers,
        [MitreAttackTechniqueAttribute(MitreAttackMainTechnique.CredentialAccess, "T1003", "OS Credential Dumping")]
        OSCredentialDumping,
        [MitreAttackTechniqueAttribute(MitreAttackMainTechnique.CredentialAccess, "T1552", "Unsecured Credentials")]
        UnsecuredCredentials,
        [MitreAttackTechniqueAttribute(MitreAttackMainTechnique.CredentialAccess, "T1110", "003", "Brute Force", "Password Spraying")]
        BruteForcePasswordSpraying,
        [MitreAttackTechniqueAttribute(MitreAttackMainTechnique.CredentialAccess, "T1187", "Forced Authentication")]
        ForcedAuthentication,
        [MitreAttackTechniqueAttribute(MitreAttackMainTechnique.CredentialAccess, "T1557", "Man-in-the-Middle")]
        ManintheMiddle,
        [MitreAttackTechniqueAttribute(MitreAttackMainTechnique.CredentialAccess, "T1557", "001", "Man-in-the-Middle", "LLMNR/NBT-NS Poisoning and SMB Relay")]
        ManintheMiddleLLMNRNBTNSPoisoningandSMBRelay,
        [MitreAttackTechniqueAttribute(MitreAttackMainTechnique.CredentialAccess, "T111", "Two-Factor Authentication Interception")]
        TwoFactorAuthenticationInterception,
        [MitreAttackTechniqueAttribute(MitreAttackMainTechnique.CredentialAccess, "T1110", "002", "Brute Force", "Password Cracking")]
        BruteForcePasswordCracking,
        [MitreAttackTechniqueAttribute(MitreAttackMainTechnique.CredentialAccess, "T1552", "006", "Unsecured Credentials", "Group Policy Preferences")]
        UnsecuredCredentialsGroupPolicyPreferences,
        [MitreAttackTechniqueAttribute(MitreAttackMainTechnique.CredentialAccess, "T1003", "004", "OS Credential Dumping", "LSA Secrets")]
        OSCredentialDumpingLSASecrets,
        [MitreAttackTechniqueAttribute(MitreAttackMainTechnique.Discovery, "T1018", "Remote System Discovery")]
        RemoteSystemDiscovery,
        [MitreAttackTechniqueAttribute(MitreAttackMainTechnique.Discovery, "T1087", "001", "Account Discovery", "Local Account")]
        AccountDiscoveryLocalAccount,
        [MitreAttackTechniqueAttribute(MitreAttackMainTechnique.Discovery, "T1069", "002", "Permission Groups Discovery", "Domain Groups")]
        PermissionGroupsDiscoveryDomainGroups,
        [MitreAttackTechniqueAttribute(MitreAttackMainTechnique.Discovery, "T1201", "Password Policy Discovery")]
        PasswordPolicyDiscovery,
        [MitreAttackTechniqueAttribute(MitreAttackMainTechnique.LateralMovement, "T1563", "Remote Service Session Hijacking")]
        RemoteServiceSessionHijacking,
        [MitreAttackTechniqueAttribute(MitreAttackMainTechnique.LateralMovement, "T1210", "Exploitation of Remote Services")]
        ExploitationofRemoteServices,
        [MitreAttackTechniqueAttribute(MitreAttackMainTechnique.Execution, "T1569", "System Services")]
        SystemServices,
        [MitreAttackTechniqueAttribute(MitreAttackMainTechnique.Persistence, "T1098", "Account Manipulation")]
        AccountManipulation,
    }

    public class MitreAttackTechniqueAttribute : Attribute
    {
        public MitreAttackTechniqueAttribute(MitreAttackMainTechnique main, string ID, string Label)
            : this(main, ID, null, Label, null)
        {
        }

        public MitreAttackTechniqueAttribute(MitreAttackMainTechnique main, string ID, string SubID, string Label, string SubLabel)
        {
            this.ID = ID;
            this.SubID = SubID;
            this.Label = Label;
            this.SubLabel = SubLabel;
            this.Main = main;
        }

        public string ID { get; set; }
        public string SubID { get; set; }
        public string SubLabel { get; set; }
        public string Label { get; set; }
        public MitreAttackMainTechnique Main { get; set; }
    }

    [AttributeUsage(AttributeTargets.Class, Inherited = false, AllowMultiple = false)]
    public class RuleMitreAttackTechniqueAttribute : RuleFrameworkReference
    {
        public RuleMitreAttackTechniqueAttribute(MitreAttackTechnique technique)
        {
            var memInfo = typeof(MitreAttackTechnique).GetMember(technique.ToString());
            var attributes = memInfo[0].GetCustomAttributes(typeof(MitreAttackTechniqueAttribute), false);
            var mit = ((MitreAttackTechniqueAttribute)attributes[0]);
            ID = mit.ID;
            SubID = mit.SubID;
            Country = "mitre";
            Label = ID + (!string.IsNullOrEmpty(SubID) ? "." + SubID : null) + " " + mit.Label + (!string.IsNullOrEmpty(mit.SubLabel) ? ": " + mit.SubLabel : null);
            MainTechnique = mit.Main;
        }

        public string ID { get; private set; }
        public string SubID { get; private set; }
        public MitreAttackMainTechnique MainTechnique { get; private set; }
        public override string URL
        {
            get
            {
                return "https://attack.mitre.org/techniques/" + ID + (!string.IsNullOrEmpty(SubID) ? "/" + SubID : null);
            }
        }
    }

    public class MitreAttackMitigationAttribute : Attribute
    {
        public MitreAttackMitigationAttribute(string ID, string Label)
        {
            this.ID = ID;
            this.Label = Label;
        }

        public string ID { get; set; }
        public string Label { get; set; }
    }


    public enum MitreAttackMitigation
    {
        [Description("Audit")]
        [MitreAttackMitigation("M1047", "Audit")]
        Audit,
        [Description("Active Directory Configuration")]
        [MitreAttackMitigation("M1015", "Active Directory Configuration")]
        ActiveDirectoryConfiguration,
        [Description("Data Backup")]
        [MitreAttackMitigation("M1053", "Data Backup")]
        DataBackup,
        [Description("Privileged Account Management")]
        [MitreAttackMitigation("M1026", "Privileged Account Management")]
        PrivilegedAccountManagement,
        [Description("Privileged Process Integrity")]
        [MitreAttackMitigation("M1025", "Privileged Process Integrity")]
        PrivilegedProcessIntegrity,
        [Description("Update Software")]
        [MitreAttackMitigation("M1051", "Update Software")]
        UpdateSoftware,
        [Description("User Account Management")]
        [MitreAttackMitigation("M1018", "User Account Management")]
        UserAccountManagement,
    }

    [AttributeUsage(AttributeTargets.Class, Inherited = false, AllowMultiple = false)]
    public class RuleMitreAttackMitigationAttribute : RuleFrameworkReference
    {

        public RuleMitreAttackMitigationAttribute(MitreAttackMitigation mitigation)
        {
            var memInfo = typeof(MitreAttackMitigation).GetMember(mitigation.ToString());
            var attributes = memInfo[0].GetCustomAttributes(typeof(MitreAttackMitigationAttribute), false);
            var mit = ((MitreAttackMitigationAttribute)attributes[0]);
            ID = mit.ID;
            Country = "mitre";
            Label = "Mitre Att&ck - Mitigation - " + mit.Label;
            MainTechnique = mitigation;
        }

        public string ID { get; private set; }
        public string SubID { get; private set; }
        public MitreAttackMitigation MainTechnique { get; private set; }
        public override string URL
        {
            get
            {
                return "https://attack.mitre.org/mitigations/" + ID + (!string.IsNullOrEmpty(SubID) ? "/" + SubID : null);
            }
        }
    }
}
