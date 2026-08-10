//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;

namespace PingCastle.Rules
{
    public sealed class MitreTechniqueInfo
    {
        public MitreTechniqueInfo(MitreAttackMainTechnique main, string id, string subId, string label, string subLabel)
        {
            Main = main;
            ID = id;
            SubID = subId ?? string.Empty;
            Label = label;
            SubLabel = subLabel ?? string.Empty;
        }

        public MitreAttackMainTechnique Main { get; }
        public string ID { get; }
        public string SubID { get; }
        public string Label { get; }
        public string SubLabel { get; }
    }

    public sealed class MitreMitigationInfo
    {
        public MitreMitigationInfo(MitreAttackMitigation mitigation, string id, string label)
        {
            Mitigation = mitigation;
            ID = id;
            Label = label;
        }

        public MitreAttackMitigation Mitigation { get; }
        public string ID { get; }
        public string Label { get; }
    }

    /// <summary>
    /// Static lookup for MITRE ATT&amp;CK techniques and mitigations referenced by Entra ID
    /// risk definitions. Metadata-driven risk rules carry raw MITRE IDs (e.g. "T1078.004",
    /// "M1026") which are resolved through this catalog for display in the MITRE ATT&amp;CK
    /// section of the report.
    /// </summary>
    public static class MitreAttackCatalog
    {
        private static readonly Dictionary<string, MitreTechniqueInfo> _techniques = BuildTechniques();
        private static readonly Dictionary<string, MitreMitigationInfo> _mitigations = BuildMitigations();

        public static IReadOnlyDictionary<string, MitreTechniqueInfo> Techniques => _techniques;
        public static IReadOnlyDictionary<string, MitreMitigationInfo> Mitigations => _mitigations;

        /// <summary>
        /// Resolves a MITRE ATT&amp;CK technique reference (e.g. "T1078.004" or "T1078") into
        /// its catalog entry. Sub-technique IDs fall back to the parent when unknown.
        /// </summary>
        public static bool TryGetTechnique(string reference, out MitreTechniqueInfo info)
        {
            info = null;
            if (string.IsNullOrWhiteSpace(reference))
            {
                return false;
            }

            var key = reference.Trim();
            if (_techniques.TryGetValue(key, out info))
            {
                return true;
            }

            var dot = key.IndexOf('.');
            if (dot > 0)
            {
                var parent = key.Substring(0, dot);
                if (_techniques.TryGetValue(parent, out info))
                {
                    return true;
                }
            }

            return false;
        }

        public static bool TryGetMitigation(string reference, out MitreMitigationInfo info)
        {
            info = null;
            if (string.IsNullOrWhiteSpace(reference))
            {
                return false;
            }

            return _mitigations.TryGetValue(reference.Trim(), out info);
        }

        private static Dictionary<string, MitreTechniqueInfo> BuildTechniques()
        {
            var d = new Dictionary<string, MitreTechniqueInfo>(StringComparer.OrdinalIgnoreCase);
            void Add(string id, string subId, MitreAttackMainTechnique main, string label, string subLabel)
            {
                var key = string.IsNullOrEmpty(subId) ? id : id + "." + subId;
                d[key] = new MitreTechniqueInfo(main, id, subId ?? string.Empty, label, subLabel ?? string.Empty);
            }

            Add("T1020", null, MitreAttackMainTechnique.Exfiltration, "Automated Exfiltration", null);
            Add("T1021", null, MitreAttackMainTechnique.LateralMovement, "Remote Services", null);
            Add("T1027", null, MitreAttackMainTechnique.DefenseEvasion, "Obfuscated Files or Information", null);
            Add("T1048", null, MitreAttackMainTechnique.Exfiltration, "Exfiltration Over Alternative Protocol", null);
            Add("T1048", "003", MitreAttackMainTechnique.Exfiltration, "Exfiltration Over Alternative Protocol", "Exfiltration Over Unencrypted Non-C2 Protocol");
            Add("T1078", null, MitreAttackMainTechnique.InitialAccess, "Valid Accounts", null);
            Add("T1078", "001", MitreAttackMainTechnique.InitialAccess, "Valid Accounts", "Default Accounts");
            Add("T1078", "004", MitreAttackMainTechnique.InitialAccess, "Valid Accounts", "Cloud Accounts");
            Add("T1087", "003", MitreAttackMainTechnique.Discovery, "Account Discovery", "Email Account");
            Add("T1087", "004", MitreAttackMainTechnique.Discovery, "Account Discovery", "Cloud Account");
            Add("T1098", null, MitreAttackMainTechnique.Persistence, "Account Manipulation", null);
            Add("T1098", "001", MitreAttackMainTechnique.Persistence, "Account Manipulation", "Additional Cloud Credentials");
            Add("T1098", "003", MitreAttackMainTechnique.Persistence, "Account Manipulation", "Additional Cloud Roles");
            Add("T1110", null, MitreAttackMainTechnique.CredentialAccess, "Brute Force", null);
            Add("T1110", "001", MitreAttackMainTechnique.CredentialAccess, "Brute Force", "Password Guessing");
            Add("T1110", "002", MitreAttackMainTechnique.CredentialAccess, "Brute Force", "Password Cracking");
            Add("T1110", "003", MitreAttackMainTechnique.CredentialAccess, "Brute Force", "Password Spraying");
            Add("T1110", "004", MitreAttackMainTechnique.CredentialAccess, "Brute Force", "Credential Stuffing");
            Add("T1114", null, MitreAttackMainTechnique.Collection, "Email Collection", null);
            Add("T1114", "003", MitreAttackMainTechnique.Collection, "Email Collection", "Email Forwarding Rule");
            Add("T1136", "003", MitreAttackMainTechnique.Persistence, "Create Account", "Cloud Account");
            Add("T1137", null, MitreAttackMainTechnique.Persistence, "Office Application Startup", null);
            Add("T1187", null, MitreAttackMainTechnique.CredentialAccess, "Forced Authentication", null);
            Add("T1199", null, MitreAttackMainTechnique.InitialAccess, "Trusted Relationship", null);
            Add("T1204", null, MitreAttackMainTechnique.Execution, "User Execution", null);
            Add("T1204", "001", MitreAttackMainTechnique.Execution, "User Execution", "Malicious Link");
            Add("T1204", "002", MitreAttackMainTechnique.Execution, "User Execution", "Malicious File");
            Add("T1213", "002", MitreAttackMainTechnique.Collection, "Data from Information Repositories", "SharePoint");
            Add("T1490", null, MitreAttackMainTechnique.Impact, "Inhibit System Recovery", null);
            Add("T1526", null, MitreAttackMainTechnique.Discovery, "Cloud Service Discovery", null);
            Add("T1530", null, MitreAttackMainTechnique.Collection, "Data from Cloud Storage", null);
            Add("T1531", null, MitreAttackMainTechnique.Impact, "Account Access Removal", null);
            Add("T1537", null, MitreAttackMainTechnique.Exfiltration, "Transfer Data to Cloud Account", null);
            Add("T1552", "001", MitreAttackMainTechnique.CredentialAccess, "Unsecured Credentials", "Credentials In Files");
            Add("T1552", "004", MitreAttackMainTechnique.CredentialAccess, "Unsecured Credentials", "Private Keys");
            Add("T1556", null, MitreAttackMainTechnique.CredentialAccess, "Modify Authentication Process", null);
            Add("T1556", "004", MitreAttackMainTechnique.CredentialAccess, "Modify Authentication Process", "Network Provider DLL");
            Add("T1556", "007", MitreAttackMainTechnique.CredentialAccess, "Modify Authentication Process", "Hybrid Identity");
            Add("T1557", null, MitreAttackMainTechnique.CredentialAccess, "Adversary-in-the-Middle", null);
            Add("T1557", "002", MitreAttackMainTechnique.CredentialAccess, "Adversary-in-the-Middle", "ARP Cache Poisoning");
            Add("T1561", "002", MitreAttackMainTechnique.Impact, "Disk Wipe", "Disk Structure Wipe");
            Add("T1562", "008", MitreAttackMainTechnique.DefenseEvasion, "Impair Defenses", "Disable or Modify Cloud Logs");
            Add("T1566", null, MitreAttackMainTechnique.InitialAccess, "Phishing", null);
            Add("T1566", "001", MitreAttackMainTechnique.InitialAccess, "Phishing", "Spearphishing Attachment");
            Add("T1566", "002", MitreAttackMainTechnique.InitialAccess, "Phishing", "Spearphishing Link");
            Add("T1566", "003", MitreAttackMainTechnique.InitialAccess, "Phishing", "Spearphishing via Service");
            Add("T1567", null, MitreAttackMainTechnique.Exfiltration, "Exfiltration Over Web Service", null);
            Add("T1567", "002", MitreAttackMainTechnique.Exfiltration, "Exfiltration Over Web Service", "Exfiltration to Cloud Storage");
            Add("T1583", "001", MitreAttackMainTechnique.ResourceDevelopment, "Acquire Infrastructure", "Domains");
            Add("T1584", "001", MitreAttackMainTechnique.ResourceDevelopment, "Compromise Infrastructure", "Domains");
            Add("T1584", "002", MitreAttackMainTechnique.ResourceDevelopment, "Compromise Infrastructure", "DNS Server");
            Add("T1589", "001", MitreAttackMainTechnique.Reconnaissance, "Gather Victim Identity Information", "Credentials");
            Add("T1621", null, MitreAttackMainTechnique.CredentialAccess, "Multi-Factor Authentication Request Generation", null);
            Add("T1651", null, MitreAttackMainTechnique.Execution, "Cloud Administration Command", null);
            Add("T1656", null, MitreAttackMainTechnique.DefenseEvasion, "Impersonation", null);

            return d;
        }

        private static Dictionary<string, MitreMitigationInfo> BuildMitigations()
        {
            var d = new Dictionary<string, MitreMitigationInfo>(StringComparer.OrdinalIgnoreCase);
            void Add(string id, MitreAttackMitigation m, string label)
            {
                d[id] = new MitreMitigationInfo(m, id, label);
            }

            Add("M1015", MitreAttackMitigation.ActiveDirectoryConfiguration, "Active Directory Configuration");
            Add("M1017", MitreAttackMitigation.UserTraining, "User Training");
            Add("M1018", MitreAttackMitigation.UserAccountManagement, "User Account Management");
            Add("M1021", MitreAttackMitigation.RestrictWebBasedContent, "Restrict Web-Based Content");
            Add("M1022", MitreAttackMitigation.RestrictFileAndDirectoryPermissions, "Restrict File and Directory Permissions");
            Add("M1024", MitreAttackMitigation.RestrictRegistryPermissions, "Restrict Registry Permissions");
            Add("M1025", MitreAttackMitigation.PrivilegedProcessIntegrity, "Privileged Process Integrity");
            Add("M1026", MitreAttackMitigation.PrivilegedAccountManagement, "Privileged Account Management");
            Add("M1027", MitreAttackMitigation.PasswordPolicies, "Password Policies");
            Add("M1030", MitreAttackMitigation.NetworkSegmentation, "Network Segmentation");
            Add("M1031", MitreAttackMitigation.NetworkIntrusionPrevention, "Network Intrusion Prevention");
            Add("M1032", MitreAttackMitigation.MultiFactorAuthentication, "Multi-factor Authentication");
            Add("M1036", MitreAttackMitigation.AccountUsePolicies, "Account Use Policies");
            Add("M1037", MitreAttackMitigation.FilterNetworkTraffic, "Filter Network Traffic");
            Add("M1041", MitreAttackMitigation.EncryptSensitiveInformation, "Encrypt Sensitive Information");
            Add("M1042", MitreAttackMitigation.DisableOrRemoveFeatureOrProgram, "Disable or Remove Feature or Program");
            Add("M1046", MitreAttackMitigation.BootIntegrity, "Boot Integrity");
            Add("M1047", MitreAttackMitigation.Audit, "Audit");
            Add("M1049", MitreAttackMitigation.AntivirusAntimalware, "Antivirus/Antimalware");
            Add("M1050", MitreAttackMitigation.ExploitProtection, "Exploit Protection");
            Add("M1051", MitreAttackMitigation.UpdateSoftware, "Update Software");
            Add("M1053", MitreAttackMitigation.DataBackup, "Data Backup");
            Add("M1054", MitreAttackMitigation.SoftwareConfiguration, "Software Configuration");
            Add("M1056", MitreAttackMitigation.PreCompromise, "Pre-compromise");

            return d;
        }
    }
}
