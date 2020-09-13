//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//

using PingCastle.Rules;

namespace PingCastle.HealthCheck.Rules
{
	[RuleModel("A-DsHeuristicsAnonymous", RiskRuleCategory.Anomalies, RiskModelCategory.Reconnaissance)]
	[RuleComputation(RuleComputationType.TriggerOnPresence, 5)]
	[RuleSTIG("V-8555", "Anonymous Access to AD forest data above the rootDSE level must be disabled. ", STIGFramework.Forest)]
    [RuleDurANSSI(2, "dsheuristics_bad", "Dangerous dsHeuristics settings")]
    public class HealthCheckRuleAnomalyDsHeuristicsAnonymous : RuleBase<HealthCheckData>
    {
		protected override int? AnalyzeDataNew(HealthCheckData healthcheckData)
        {
            if (healthcheckData.DsHeuristicsAnonymousAccess)
            {
                return 1;
            }
            return 0;
        }
    }
}
