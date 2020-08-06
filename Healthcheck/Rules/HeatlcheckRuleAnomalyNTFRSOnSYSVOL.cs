//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.Text;
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
	[RuleModel("A-NTFRSOnSysvol", RiskRuleCategory.Anomalies, RiskModelCategory.NetworkSniffing)]
	[RuleComputation(RuleComputationType.TriggerOnPresence, 5)]
	[RuleIntroducedIn(2, 9)]
    [RuleDurANSSI(2, "sysvol_ntfrs", "SYSVOL replication through NTFRS")]
    public class HeatlcheckRuleAnomalyNTFRSOnSYSVOL : RuleBase<HealthcheckData>
	{
		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
		{
			if (healthcheckData.UsingNTFRSForSYSVOL)
				return 1;
			return 0;
		}
	}
}
