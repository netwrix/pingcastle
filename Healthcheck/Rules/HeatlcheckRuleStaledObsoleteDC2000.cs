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
	[HeatlcheckRuleModel("S-DC-2000", HealthcheckRiskRuleCategory.StaleObjects, HealthcheckRiskModelCategory.ObsoleteOS)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnPresence, 40)]
    [HeatlcheckRuleSTIG("V-8551")]
    public class HeatlcheckRuleStaledObsoleteDC2000 : HeatlcheckRuleBase
    {
		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
			int w2000 = 0;
			foreach (var dc in healthcheckData.DomainControllers)
			{
				if (dc.OperatingSystem == "Windows 2000")
				{
					w2000++;
				}
			}
			return w2000;
        }
    }
}
