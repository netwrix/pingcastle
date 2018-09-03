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
	[HeatlcheckRuleModel("P-DangerousExtendedRight", HealthcheckRiskRuleCategory.PrivilegedAccounts, HealthcheckRiskModelCategory.ACLCheck)]
	[HeatlcheckRuleComputation(RuleComputationType.PerDiscover, 5)]
    public class HeatlcheckRulePrivilegedDangerousDelegation : HeatlcheckRuleBase
    {
		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            foreach (HealthcheckDelegationData delegation in healthcheckData.Delegations)
            {
                if (delegation.Right.Contains("EXT_RIGHT_REANIMATE_TOMBSTONE") || delegation.Right.Contains("EXT_RIGHT_UNEXPIRE_PASSWORD") || delegation.Right.Contains("EXT_RIGHT_MIGRATE_SID_HISTORY"))
                {
                    AddRawDetail(delegation.DistinguishedName, delegation.Account, delegation.Right);
                }
            }
            return null;
        }
    }
}
