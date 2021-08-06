//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("S-C-Inactive", RiskRuleCategory.StaleObjects, RiskModelCategory.InactiveUserOrComputer)]
    [RuleComputation(RuleComputationType.TriggerOnThreshold, 30, Threshold: 30, Order: 1)]
    [RuleComputation(RuleComputationType.TriggerOnThreshold, 10, Threshold: 20, Order: 2)]
    [RuleComputation(RuleComputationType.TriggerOnThreshold, 5, Threshold: 15, Order: 3)]
    [RuleANSSI("R45", "paragraph.3.6.6.2")]
    [RuleDurANSSI(3, "password_change_inactive_servers", "Inactive servers")]
    [RuleMitreAttackMitigation(MitreAttackMitigation.UserAccountManagement)]
    public class HeatlcheckRuleStaledInactiveComputer : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.ComputerAccountData.NumberActive <= 20)
                return 0;
            if (healthcheckData.ComputerAccountData.Number == 0)
                return 0;
            return 100 * healthcheckData.ComputerAccountData.NumberInactive / healthcheckData.ComputerAccountData.Number;
        }
    }
}
