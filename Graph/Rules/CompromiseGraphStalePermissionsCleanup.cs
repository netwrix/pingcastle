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
	[RuleObjectiveAttribute("S-PermissionsCleanup", RiskRuleCategory.StaleObjects, RiskModelObjective.StaleObjectsHouseKeeping)]
	[RuleComputation(RuleComputationType.Objective, 25)]
	public class CompromiseGraphStalePermissionsCleanup : CompromiseGraphRule
	{
		protected override int? AnalyzeDataNew(CompromiseGraphData compromiseGraphData)
		{
			foreach (var single in compromiseGraphData.Data)
			{
				if (single.Typology != CompromiseGraphDataTypology.PrivilegedAccount && single.Typology != CompromiseGraphDataTypology.PrivilegedAccount)
					continue;
				if (single.DeletedObjects != null && single.DeletedObjects.Count > 0)
					return 1;
				
			}
			return -1;
		}
	}
}
