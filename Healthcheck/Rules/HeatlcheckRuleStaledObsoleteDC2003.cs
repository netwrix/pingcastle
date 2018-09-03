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
	[HeatlcheckRuleModel("S-DC-2003", HealthcheckRiskRuleCategory.StaleObjects, HealthcheckRiskModelCategory.ObsoleteOS)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnPresence, 20)]
    [HeatlcheckRuleSTIG("V-8551")]
    public class HeatlcheckRuleStaledObsoleteDC2003 : HeatlcheckRuleBase
    {
		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
			int w2003 = 0;
            foreach (var dc in healthcheckData.DomainControllers)
            {
                if (dc.OperatingSystem == "Windows 2003")
                {
                    w2003++;
                }
            }
			return w2003;
        }
    }
}
