//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using PingCastle.Rules;
using PingCastle.Data;

namespace PingCastle.Graph.Rules
{
	[RuleObjectiveAttribute("T-OneDomainControlUserDefined", RiskRuleCategory.Trusts, RiskModelObjective.TrustPermeability)]
	[RuleComputation(RuleComputationType.Objective, 20)]
	public class CompromiseGraphTrustOneDomainControlUserDefined : CompromiseGraphRule
	{
		protected override int? AnalyzeDataNew(CompromiseGraphData compromiseGraphData)
		{
			foreach (var single in compromiseGraphData.Dependancies)
			{
				foreach (var detail in single.Details)
				{
					if (detail.Typology == CompromiseGraphDataTypology.UserDefined)
					{
						return 1;
					}
				}
			}
			return -1;
		}
	}
}
