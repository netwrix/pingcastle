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
using PingCastle.Data;

namespace PingCastle.Graph.Rules
{
	[RuleObjectiveAttribute("P-OperatorsEmpty", RiskRuleCategory.PrivilegedAccounts, RiskModelObjective.PrivilegedBestPractices)]
	[RuleComputation(RuleComputationType.Objective, 25)]
	[RuleANSSI("R27", "subsection.3.5")]
	[RuleIntroducedIn(2, 6)]
	public class CompromiseGraphPrivilegedOperatorsEmpty : CompromiseGraphRule
	{
		protected override int? AnalyzeDataNew(CompromiseGraphData compromiseGraphData)
		{
			foreach (var single in compromiseGraphData.Data)
			{
				if (single.Typology != CompromiseGraphDataTypology.PrivilegedAccount)
					continue;
				if (single.Name != "S-1-5-32-548" && single.Name != "S-1-5-32-549")
					continue;
				foreach (var obj in single.Nodes)
				{
					if (obj.Type != "user")
						continue;
					if (obj.Suspicious)
						continue;
					return 1;
				}
			}
			return -1;
		}
	}
}
