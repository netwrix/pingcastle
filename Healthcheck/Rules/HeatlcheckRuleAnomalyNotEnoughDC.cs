//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-NotEnoughDC", RiskRuleCategory.Anomalies, RiskModelCategory.Backup)]
    [RuleComputation(RuleComputationType.TriggerIfLessThan, 5, Threshold: 2)]
    [RuleIntroducedIn(2, 6)]
    [RuleMaturityLevel(3)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.DataBackup)]
    public class HeatlcheckRuleAnomalyNotEnoughDC : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            return healthcheckData.NumberOfDC;
        }
    }
}
