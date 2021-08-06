//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("S-PwdNeverExpires", RiskRuleCategory.StaleObjects, RiskModelCategory.ObjectConfig)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 1)]
    [RuleIntroducedIn(2, 9)]
    [RuleDurANSSI(2, "dont_expire", "Accounts with never-expiring passwords")]
    [RuleMitreAttackMitigation(MitreAttackMitigation.ActiveDirectoryConfiguration)]
    public class HeatlcheckRuleStaledPwdNeverExpires : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            return healthcheckData.UserAccountData.NumberPwdNeverExpires;
        }
    }
}
