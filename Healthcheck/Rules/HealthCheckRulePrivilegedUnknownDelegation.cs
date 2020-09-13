//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using PingCastle.Rules;

namespace PingCastle.HealthCheck.Rules
{
	[RuleModel("P-UnkownDelegation", RiskRuleCategory.PrivilegedAccounts, RiskModelCategory.DelegationCheck)]
	[RuleComputation(RuleComputationType.TriggerOnPresence, 15)]
	[RuleSTIG("V-2370", "The access control permissions for the directory service site group policy must be configured to use the required access permissions.", STIGFramework.ActiveDirectoryService2003)]
    [RuleMaturityLevel(4)]
    public class HealthCheckRulePrivilegedUnknownDelegation : RuleBase<HealthCheckData>
    {
		protected override int? AnalyzeDataNew(HealthCheckData healthcheckData)
        {
            foreach (HealthCheckDelegationData delegation in healthcheckData.Delegations)
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
