//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.Text;
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
	[RuleModel("A-MembershipEveryone", RiskRuleCategory.Anomalies, RiskModelCategory.LocalGroupVulnerability)]
	[RuleComputation(RuleComputationType.PerDiscover, 15)]
    [RuleMaturityLevel(1)]
    public class HeatlcheckRuleAnomalyMembershipEveryone : RuleBase<HealthcheckData>
    {
		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            foreach (GPOMembership membership in healthcheckData.GPOLocalMembership)
            {
				if (membership.User == "Authenticated Users" || membership.User == "Everyone" || membership.User == "Users" || membership.User == "Anonymous")
                {
                    if (string.Equals(membership.MemberOf, "BUILTIN\\Users", StringComparison.OrdinalIgnoreCase))
                        continue;
                    AddRawDetail(membership.GPOName, membership.MemberOf, membership.User);
                }
            }
            return null;
        }
    }
}
