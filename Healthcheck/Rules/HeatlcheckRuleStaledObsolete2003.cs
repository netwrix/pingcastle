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
	[HeatlcheckRuleModel("S-OS-2003", HealthcheckRiskRuleCategory.StaleObjects, HealthcheckRiskModelCategory.ObsoleteOS)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnThreshold, 30, Threshold: 15, Order: 1)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnThreshold, 25, Threshold: 6, Order: 2)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnPresence, 20, Order: 3)]
    public class HeatlcheckRuleStaledObsolete2003 : HeatlcheckRuleBase
    {
		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            foreach (HealthcheckOSData os in healthcheckData.OperatingSystem)
            {
                if (os.OperatingSystem == "Windows 2003")
                {
                    return os.NumberOfOccurence;
                }
            }
            return 0;
        }
    }
}
