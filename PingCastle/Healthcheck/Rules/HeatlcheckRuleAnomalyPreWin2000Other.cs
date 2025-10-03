//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-PreWin2000Other", RiskRuleCategory.Anomalies, RiskModelCategory.Reconnaissance)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 2)]
    [RuleIntroducedIn(2, 9)]
    [RuleDurANSSI(3, "compatible_2000_not_default", "Use of the \"Pre-Windows 2000 Compatible Access\" group")]
    [RuleMitreAttackTechnique(MitreAttackTechnique.BruteForcePasswordSpraying)]
    public class HeatlcheckRuleAnomalyPreWin2000Other : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.PreWindows2000NoDefault)
            {
                for (int i = 0; i < healthcheckData.PreWindows2000Members.Count; i++)
                {
                    AddRawDetail(healthcheckData.PreWindows2000Members[i]);
                }
            }
            return null;
        }
    }
}
