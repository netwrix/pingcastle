//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
	[RuleModel("S-DC-Inactive", RiskRuleCategory.StaleObjects, RiskModelCategory.InactiveUserOrComputer)]
	[RuleComputation(RuleComputationType.PerDiscover, 5)]
	[RuleANSSI("R45", "paragraph.3.6.6.2")]
    [RuleDurANSSI(1, "password_change_inactive_dc", "Inactive domain controllers")]
    [RuleIntroducedIn(2,9)]
    public class HeatlcheckRuleStaledInactiveDC : RuleBase<HealthcheckData>
    {
		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            foreach (var dc in healthcheckData.DomainControllers)
            {
                if (dc.LastComputerLogonDate < DateTime.Now.AddDays(-45))
                {
                    AddRawDetail(dc.DCName, dc.LastComputerLogonDate.ToString("u"));
                }
            }
            return null;
        }
    }
}
