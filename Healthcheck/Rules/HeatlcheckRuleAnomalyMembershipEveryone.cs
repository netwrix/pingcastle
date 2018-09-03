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
	[HeatlcheckRuleModel("A-MembershipEveryone", HealthcheckRiskRuleCategory.Anomalies, HealthcheckRiskModelCategory.LocalGroupVulnerability)]
	[HeatlcheckRuleComputation(RuleComputationType.PerDiscover, 15)]
    public class HeatlcheckRuleAnomalyMembershipEveryone : HeatlcheckRuleBase
    {
		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            foreach (GPOMembership membership in healthcheckData.GPOLocalMembership)
            {
                if (membership.User == "Authenticated Users" || membership.User == "Everyone")
                {
                    AddRawDetail(membership.GPOName, membership.MemberOf, membership.User);
                }
            }
            return null;
        }
    }
}
