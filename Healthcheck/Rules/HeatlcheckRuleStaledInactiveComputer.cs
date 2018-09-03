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
	[HeatlcheckRuleModel("S-C-Inactive", HealthcheckRiskRuleCategory.StaleObjects, HealthcheckRiskModelCategory.InactiveUserOrComputer)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnThreshold, 30, Threshold: 30, Order: 1)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnThreshold, 10, Threshold: 20, Order: 2)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnThreshold, 5, Threshold: 15, Order: 3)]
    public class HeatlcheckRuleStaledInactiveComputer : HeatlcheckRuleBase
    {
		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
			if (healthcheckData.ComputerAccountData.NumberActive <= 20)
				return 0;
			if (healthcheckData.ComputerAccountData.Number == 0)
				return 0;
			return 100 * healthcheckData.ComputerAccountData.NumberInactive / healthcheckData.ComputerAccountData.Number;
        }
    }
}
