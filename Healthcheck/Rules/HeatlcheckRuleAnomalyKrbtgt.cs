//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.Text;

namespace PingCastle.Healthcheck.Rules
{
	[HeatlcheckRuleModel("A-Krbtgt", HealthcheckRiskRuleCategory.Anomalies, HealthcheckRiskModelCategory.GoldenTicket)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnThreshold, 50, Threshold: 732, Order: 1)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnThreshold, 40, Threshold: 366, Order: 2)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnThreshold, 30, Threshold: 180, Order: 3)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnThreshold, 20, Threshold: 70, Order: 4)]
    public class HeatlcheckRuleAnomalyKrbtgt : HeatlcheckRuleBase
    {
		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
			return (int)(healthcheckData.GenerationDate - healthcheckData.KrbtgtLastChangeDate).TotalDays;
        }
    }
}
