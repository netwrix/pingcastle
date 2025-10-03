//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System.ComponentModel;

namespace PingCastle.Rules
{

    public enum RiskModelCategory
    {
        Unknown = 0,
        [Description("Inactive user or computer")]
        InactiveUserOrComputer = 1000,
        [Description("Vulnerability management")]
        VulnerabilityManagement = 1001,
        [Description("Replication")]
        Replication = 1002,
        [Description("Provisioning")]
        Provisioning = 1003,
        [Description("Old authentication protocols")]
        OldAuthenticationProtocols = 1004,
        [Description("Obsolete OS")]
        ObsoleteOS = 1005,
        [Description("Object configuration")]
        ObjectConfig = 1006,
        [Description("Network topography")]
        NetworkTopography = 1007,
        [Description("Admin control")]
        AdminControl = 2000,
        [Description("Privilege control")]
        PrivilegeControl = 2001,
        [Description("ACL Check")]
        ACLCheck = 2002,
        [Description("Irreversible change")]
        IrreversibleChange = 2003,
        [Description("Account take over")]
        AccountTakeOver = 2004,
        [Description("Control paths")]
        ControlPath = 2005,
        [Description("Delegation Check")]
        DelegationCheck = 2006,
        [Description("Read-Only Domain Controllers")]
        RODC = 2007,
        [Description("SID Filtering")]
        SIDFiltering = 3000,
        [Description("Trust inactive")]
        TrustInactive = 3001,
        [Description("Trust impermeability")]
        TrustImpermeability = 3002,
        [Description("SIDHistory")]
        SIDHistory = 3003,
        [Description("Old trust protocol")]
        OldTrustProtocol = 3004,
        [Description("Trust with Entra")]
        TrustAzure = 3005,
        [Description("Reconnaissance")]
        Reconnaissance = 4000,
        [Description("Local group vulnerability")]
        LocalGroupVulnerability = 4001,
        [Description("Password retrieval")]
        PasswordRetrieval = 4002,
        [Description("Weak password")]
        WeakPassword = 4003,
        [Description("Temporary admins")]
        TemporaryAdmins = 4004,
        [Description("Network sniffing")]
        NetworkSniffing = 4005,
        [Description("Certificate take over")]
        CertificateTakeOver = 4006,
        [Description("Pass-the-credential")]
        PassTheCredential = 4007,
        [Description("Golden ticket")]
        GoldenTicket = 4008,
        [Description("Backup")]
        Backup = 4009,
        [Description("Audit")]
        Audit = 4010,
    }
}
