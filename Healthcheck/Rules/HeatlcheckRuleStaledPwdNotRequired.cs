//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("S-PwdNotRequired", RiskRuleCategory.StaleObjects, RiskModelCategory.ObjectConfig)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 15)]
    [RuleANSSI("R36", "subsection.3.6")]
    [RuleMaturityLevel(3)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.ActiveDirectoryConfiguration)]
    public class HeatlcheckRuleStaledPwdNotRequired : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            return healthcheckData.UserAccountData.NumberPwdNotRequired;
        }
    }
}
