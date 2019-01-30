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
	[RuleObjectiveAttribute("T-OneDomainControlCritical", RiskRuleCategory.Trusts, RiskModelObjective.TrustPermeability)]
	[RuleComputation(RuleComputationType.Objective, 100)]
	public class CompromiseGraphTrustMoreThanOneDomainControlCritical : CompromiseGraphTrustOneDomainControlCritical
	{
		protected override int? AnalyzeDataNew(CompromiseGraphData compromiseGraphData)
		{
			return AnalyzeDataNew(compromiseGraphData, 1);
		}
	}
}
