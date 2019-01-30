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
	[RuleObjectiveAttribute("T-ChildDomainHasPermission", RiskRuleCategory.Trusts, RiskModelObjective.TrustBestPractices)]
	[RuleComputation(RuleComputationType.Objective, 25)]
	public class CompromiseGraphTrustChildDomainHasPermission : CompromiseGraphRule
	{
		protected override int? AnalyzeDataNew(CompromiseGraphData compromiseGraphData)
		{
			foreach (var single in compromiseGraphData.Dependancies)
			{

			}
			return -1;
		}
	}
}
