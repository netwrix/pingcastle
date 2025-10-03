//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-DsHeuristicsAllowAnonNSPI", RiskRuleCategory.Anomalies, RiskModelCategory.Reconnaissance)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 5)]
    [RuleSTIG("V-8555", "Anonymous Access to AD forest data above the rootDSE level must be disabled. ", STIGFramework.Forest)]
    [RuleDurANSSI(1, "dsheuristics_bad", "Dangerous dsHeuristics settings")]
    [RuleIntroducedIn(2, 9)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.BruteForcePasswordSpraying)]
    public class HeatlcheckRuleAnomalyDsHeuristicsAnonNSPI : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.DSHeuristics != null && healthcheckData.DSHeuristics.Length >= 8 && healthcheckData.DSHeuristics.Substring(7, 1) != "0")
            {
                return 1;
            }
            return 0;
        }
    }
}
