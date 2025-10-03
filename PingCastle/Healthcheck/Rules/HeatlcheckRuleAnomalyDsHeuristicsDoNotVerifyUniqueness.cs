//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-DsHeuristicsDoNotVerifyUniqueness", RiskRuleCategory.Anomalies, RiskModelCategory.Reconnaissance)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 5)]
    [RuleDurANSSI(2, "dsheuristics_bad", "Dangerous dsHeuristics settings")]
    [RuleIntroducedIn(2, 10, 1)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.ForcedAuthentication)]
    public class HeatlcheckRuleAnomalyDsHeuristicsDoNotVerifyUniqueness : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.DSHeuristics != null && healthcheckData.DSHeuristics.Length >= 21 && healthcheckData.DSHeuristics.Substring(20, 1) != "0")
            {
                return 1;
            }
            return 0;
        }
    }
}
