//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("P-AdminNum", RiskRuleCategory.PrivilegedAccounts, RiskModelCategory.AdminControl)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 10)]
    [RuleANSSI("R26", "subsection.3.5")]
    [RuleANSSI("R30", "subsubsection.3.5.7")]
    [RuleDurANSSI(1, "privileged_members", "Large privileged group member count")]
    [RuleMitreAttackMitigation(MitreAttackMitigation.PrivilegedAccountManagement)]
    public class HeatlcheckRulePrivilegedAdminNumber : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.UserAccountData.NumberActive <= 100)
                return 0;
            if (healthcheckData.AllPrivilegedMembers.Count == 0)
                return 0;
            if ((healthcheckData.AllPrivilegedMembers.Count * 100 / healthcheckData.UserAccountData.NumberActive) > 10)
            {
                return healthcheckData.AllPrivilegedMembers.Count;
            }
            if (healthcheckData.AllPrivilegedMembers.Count > 50)
            {
                return healthcheckData.AllPrivilegedMembers.Count;
            }
            return 0;
        }
    }
}
