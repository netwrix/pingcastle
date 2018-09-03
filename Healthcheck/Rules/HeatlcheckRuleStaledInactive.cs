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
	[HeatlcheckRuleModel("S-Inactive", HealthcheckRiskRuleCategory.StaleObjects, HealthcheckRiskModelCategory.InactiveUserOrComputer)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnThreshold, 10, Threshold: 15)]
    public class HeatlcheckRuleStaledInactive : HeatlcheckRuleBase
    {
		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.UserAccountData.NumberActive <= 10)
				return 0;
			if (healthcheckData.UserAccountData.Number == 0)
				return 0;
			return 100 * healthcheckData.UserAccountData.NumberInactive / healthcheckData.UserAccountData.Number;
        }
    }
}
