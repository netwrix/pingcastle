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
	[HeatlcheckRuleModel("P-Delegated", HealthcheckRiskRuleCategory.PrivilegedAccounts, HealthcheckRiskModelCategory.ACLCheck)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnPresence, 20)]
    [HeatlcheckRuleSTIG("V-36435")]
    public class HeatlcheckRulePrivilegedDelegated : HeatlcheckRuleBase
    {
		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            int adminCanBeDelegated = 0;
            foreach (var member in healthcheckData.AllPrivilegedMembers)
            {
                if (member.CanBeDelegated)
                    adminCanBeDelegated++;
            }
			return adminCanBeDelegated;
        }
    }
}
