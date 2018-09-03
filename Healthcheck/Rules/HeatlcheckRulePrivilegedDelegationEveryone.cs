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
	[HeatlcheckRuleModel("P-DelegationEveryone", HealthcheckRiskRuleCategory.PrivilegedAccounts, HealthcheckRiskModelCategory.ACLCheck)]
	[HeatlcheckRuleComputation(RuleComputationType.PerDiscover, 15)]
    public class HeatlcheckRulePrivilegedDelegationEveryone : HeatlcheckRuleBase
    {
		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            foreach (HealthcheckDelegationData delegation in healthcheckData.Delegations)
            {
                if (delegation.Account == "Authenticated Users" || delegation.Account == "Everyone")
                {
                    AddRawDetail(delegation.DistinguishedName, delegation.Account, delegation.Right);
                }
            }
            return null;
        }
    }
}
