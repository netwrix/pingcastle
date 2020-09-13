//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//

using PingCastle.Rules;

namespace PingCastle.HealthCheck.Rules
{
    [RuleModel("A-NotEnoughDC", RiskRuleCategory.Anomalies, RiskModelCategory.Backup)]
    [RuleComputation(RuleComputationType.TriggerIfLessThan, 5, Threshold: 2)]
    [RuleIntroducedIn(2, 6)]
    [RuleMaturityLevel(3)]
    public class HealthCheckRuleAnomalyNotEnoughDC : RuleBase<HealthCheckData>
    {
        protected override int? AnalyzeDataNew(HealthCheckData healthcheckData)
        {
            return healthcheckData.NumberOfDC;
        }
    }
}