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
	[RuleModel("P-DelegationEveryone", RiskRuleCategory.PrivilegedAccounts, RiskModelCategory.ACLCheck)]
	[RuleComputation(RuleComputationType.PerDiscover, 15)]
	[RuleANSSI("R18", "subsubsection.3.3.2")]
    public class HeatlcheckRulePrivilegedDelegationEveryone : RuleBase<HealthcheckData>
    {
		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            foreach (HealthcheckDelegationData delegation in healthcheckData.Delegations)
            {
                if (delegation.Account == "Authenticated Users" || delegation.Account == "Everyone" || delegation.Account == "Domain Users" || delegation.Account == "Domain Computers")
                {
                    AddRawDetail(delegation.DistinguishedName, delegation.Account, delegation.Right);
                }
            }
            return null;
        }
    }
}
