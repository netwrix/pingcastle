//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//

using PingCastle.Rules;

namespace PingCastle.HealthCheck.Rules
{
	[RuleModel("P-DelegationGPOData", RiskRuleCategory.PrivilegedAccounts, RiskModelCategory.ACLCheck)]
	[RuleComputation(RuleComputationType.PerDiscover, 15)]
	[RuleANSSI("R18", "subsubsection.3.3.2")]
	[RuleSTIG("V-2370", "The access control permissions for the directory service site group policy must be configured to use the required access permissions.", STIGFramework.ActiveDirectoryService2003)]
	[RuleIntroducedIn(2, 6)]
    [RuleMaturityLevel(2)]
	public class HealthCheckRulePrivilegedDelegationGPOData : RuleBase<HealthCheckData>
    {
		protected override int? AnalyzeDataNew(HealthCheckData healthcheckData)
        {
			foreach (var delegation in healthcheckData.GPODelegation)
			{
				AddRawDetail(delegation.GPOName, delegation.Item, delegation.Account, delegation.Right);
			}
			return null;
        }
    }
}
