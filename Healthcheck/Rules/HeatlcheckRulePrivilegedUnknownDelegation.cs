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
	[HeatlcheckRuleModel("P-UnkownDelegation", HealthcheckRiskRuleCategory.PrivilegedAccounts, HealthcheckRiskModelCategory.ACLCheck)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnPresence, 15)]
    public class HeatlcheckRulePrivilegedUnknownDelegation : HeatlcheckRuleBase
    {
		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            foreach (HealthcheckDelegationData delegation in healthcheckData.Delegations)
            {
                if (delegation.Account.StartsWith("S-1-", StringComparison.InvariantCultureIgnoreCase))
                {
                    AddRawDetail(delegation.DistinguishedName, delegation.Account, delegation.Right);
                }
            }
            return null;
        }
    }
}
