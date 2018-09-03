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
	[HeatlcheckRuleModel("S-DC-NotUpdated", HealthcheckRiskRuleCategory.StaleObjects, HealthcheckRiskModelCategory.VulnerabilityManagement)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnPresence, 15)]
    public class HeatlcheckRuleStaledDCNotRebooted : HeatlcheckRuleBase
    {
		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.DomainControllers != null && healthcheckData.DomainControllers.Count > 0)
            {
                foreach (var DC in healthcheckData.DomainControllers)
                {
					if (DC.StartupTime != DateTime.MinValue)
					{
						if (DC.StartupTime.AddMonths(6) < DateTime.Now)
						{
							AddRawDetail(DC.DCName , "StartupTime=" + DC.StartupTime);
						}
					}
					else
					{
						if (DC.LastComputerLogonDate != DateTime.MinValue && DC.LastComputerLogonDate.AddMonths(6) < DateTime.Now)
						{
							AddRawDetail(DC.DCName, "LastComputerLogonDate=" + DC.LastComputerLogonDate);
						}
					}
                }
            }
            return null;
        }
    }
}
