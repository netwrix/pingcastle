//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("P-Inactive", RiskRuleCategory.PrivilegedAccounts, RiskModelCategory.AdminControl)]
    [RuleComputation(RuleComputationType.TriggerOnThreshold, 30, Threshold: 30, Order: 1)]
    [RuleComputation(RuleComputationType.TriggerOnThreshold, 20, Threshold: 15, Order: 2)]
    [RuleANSSI("R36", "subsection.3.6")]
    [RuleMaturityLevel(3)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.PrivilegedAccountManagement)]
    public class HeatlcheckRulePrivilegedAdminInactive : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {

            int adminEnabledAndInactive = 0;
            if (healthcheckData.AllPrivilegedMembers.Count > 20)
            {
                foreach (var member in healthcheckData.AllPrivilegedMembers)
                {
                    if (member.IsEnabled && !member.IsActive)
                        adminEnabledAndInactive++;
                }
                return 100 * adminEnabledAndInactive / healthcheckData.AllPrivilegedMembers.Count;
            }
            return 0;
        }
    }
}
