//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("S-Inactive", RiskRuleCategory.StaleObjects, RiskModelCategory.InactiveUserOrComputer)]
    [RuleComputation(RuleComputationType.TriggerOnThreshold, 10, Threshold: 25)]
    [RuleANSSI("R45", "paragraph.3.6.6.2")]
    [RuleDurANSSI(1, "user_accounts_dormant", "Dormant accounts")]
    [RuleMitreAttackMitigation(MitreAttackMitigation.UserAccountManagement)]
    public class HeatlcheckRuleStaledInactive : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.UserAccountData.NumberActive <= 10)
                return 0;
            if (healthcheckData.UserAccountData.Number == 0)
                return 0;
            return 100 * healthcheckData.UserAccountData.NumberInactive / healthcheckData.UserAccountData.Number;
        }
    }
}
