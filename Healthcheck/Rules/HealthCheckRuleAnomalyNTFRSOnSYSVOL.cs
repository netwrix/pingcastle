//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//

using PingCastle.Rules;

namespace PingCastle.HealthCheck.Rules
{
	[RuleModel("A-NTFRSOnSysvol", RiskRuleCategory.Anomalies, RiskModelCategory.NetworkSniffing)]
	[RuleComputation(RuleComputationType.TriggerOnPresence, 5)]
	[RuleIntroducedIn(2, 9)]
    [RuleDurANSSI(2, "sysvol_ntfrs", "SYSVOL replication through NTFRS")]
    public class HealthCheckRuleAnomalyNTFRSOnSYSVOL : RuleBase<HealthCheckData>
	{
		protected override int? AnalyzeDataNew(HealthCheckData healthcheckData)
		{
			if (healthcheckData.UsingNTFRSForSYSVOL)
				return 1;
			return 0;
		}
	}
}
