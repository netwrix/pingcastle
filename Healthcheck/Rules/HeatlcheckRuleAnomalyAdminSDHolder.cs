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
	[HeatlcheckRuleModel("A-AdminSDHolder", HealthcheckRiskRuleCategory.Anomalies, HealthcheckRiskModelCategory.TemporaryAdmins)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnThreshold, 50, Threshold: 50, Order: 1)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnThreshold, 45, Threshold: 45, Order: 2)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnThreshold, 40, Threshold: 40, Order: 3)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnThreshold, 35, Threshold: 35, Order: 4)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnThreshold, 30, Threshold: 30, Order: 5)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnThreshold, 25, Threshold: 25, Order: 6)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnThreshold, 20, Threshold: 20, Order: 7)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnPresence, 15, Order: 8)]
    public class HeatlcheckRuleAnomalyAdminSDHolder : HeatlcheckRuleBase
    {
		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
			return healthcheckData.AdminSDHolderNotOKCount;
        }
    }
}
