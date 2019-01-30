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
	[RuleObjectiveAttribute("A-IndirectUser", RiskRuleCategory.Anomalies, RiskModelObjective.AnomalyAccessCritical)]
	[RuleComputation(RuleComputationType.Objective, 100)]
	public abstract class CompromiseGraphAnomalyIndirectUser : CompromiseGraphRule
	{
		protected int? AnalyzeDataNew(CompromiseGraphData compromiseGraphData, CompromiseGraphDataObjectRisk risk, int trigger)
		{
			foreach (var analysis in compromiseGraphData.AnomalyAnalysis)
			{
				if (analysis.ObjectRisk != risk)
				{
					continue;
				}
				if (trigger == -1)
				{
					if (analysis.CriticalObjectFound)
						return 1;
				}
				else if (analysis.MaximumIndirectNumber > trigger)
				{
					return 1;
				}
			}
			return -1;
		}
	}
}
