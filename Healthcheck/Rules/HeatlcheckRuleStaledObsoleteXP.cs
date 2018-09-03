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
	[HeatlcheckRuleModel("S-OS-XP", HealthcheckRiskRuleCategory.StaleObjects, HealthcheckRiskModelCategory.ObsoleteOS)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnThreshold, 20, Threshold: 15, Order: 1)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnThreshold, 15, Threshold: 6, Order: 2)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnPresence, 10, Order: 3)]
    public class HeatlcheckRuleStaledObsoleteXP : HeatlcheckRuleBase
    {
		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            foreach (HealthcheckOSData os in healthcheckData.OperatingSystem)
            {
                if (os.OperatingSystem == "Windows XP")
                {
                    return os.NumberOfOccurence;
                }
            }
            return 0;
        }
    }
}
