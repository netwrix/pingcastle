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
	[HeatlcheckRuleModel("S-Vuln-MS17_010", HealthcheckRiskRuleCategory.StaleObjects, HealthcheckRiskModelCategory.VulnerabilityManagement)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnPresence, 100)]
    public class HeatlcheckRuleStaledMS17_010 : HeatlcheckRuleBase
    {
		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
			DateTime alertDate = new DateTime(2017, 03, 14);
			if (healthcheckData.DomainControllers != null && healthcheckData.DomainControllers.Count > 0)
			{
				foreach (var DC in healthcheckData.DomainControllers)
				{
					if (DC.StartupTime != DateTime.MinValue)
					{
						if (DC.StartupTime < alertDate)
						{
							AddRawDetail(DC.DCName, "StartupTime=" + DC.StartupTime);
						}
					}
					else if (DC.OperatingSystem == "Windows 2000" || DC.OperatingSystem == "Windows NT")
					{
						AddRawDetail(DC.DCName,"Operating Sytem=" + DC.OperatingSystem);
					}
				}
			}
			return null;
        }
    }
}
