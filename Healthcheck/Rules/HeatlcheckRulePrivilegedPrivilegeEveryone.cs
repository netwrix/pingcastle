using PingCastle.Graph.Reporting;
//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;
using System.Collections.Generic;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("P-PrivilegeEveryone", RiskRuleCategory.PrivilegedAccounts, RiskModelCategory.PrivilegeControl)]
    [RuleComputation(RuleComputationType.PerDiscover, 15)]
    [RuleANSSI("R18", "subsubsection.3.3.2")]
    [RuleIntroducedIn(2, 6)]
    [RuleMaturityLevel(2)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.ActiveDirectoryConfiguration)]
    public class HeatlcheckRulePrivilegedPrivilegeEveryone : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            var dangerousPrivileges = new List<string>()
            {
                "SeLoadDriverPrivilege",
                "SeTcbPrivilege",
                "SeDebugPrivilege",
                "SeRestorePrivilege",
                "SeBackupPrivilege",
                "SeTakeOwnershipPrivilege",
                "SeCreateTokenPrivilege",
                "SeImpersonatePrivilege",
                "SeAssignPrimaryTokenPrivilege",
                "SeSecurityPrivilege",
                "SeManageVolumePrivilege",
            };
            foreach (var privilege in healthcheckData.GPPRightAssignment)
            {
                if (!dangerousPrivileges.Contains(privilege.Privilege))
                    continue;
                if (privilege.User == GraphObjectReference.AuthenticatedUsers || privilege.User == GraphObjectReference.Everyone || privilege.User == GraphObjectReference.DomainUsers
                    || privilege.User == GraphObjectReference.DomainComputers || privilege.User == GraphObjectReference.Users
                    || privilege.User == GraphObjectReference.Anonymous)
                {
                    AddRawDetail(privilege.GPOName, privilege.User, privilege.Privilege);
                }
            }
            return null;
        }
    }
}
