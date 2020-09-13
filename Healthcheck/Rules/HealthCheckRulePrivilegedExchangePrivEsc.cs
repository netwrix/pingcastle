//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//

using PingCastle.Rules;

namespace PingCastle.HealthCheck.Rules
{
	[RuleModel("P-ExchangePrivEsc", RiskRuleCategory.PrivilegedAccounts, RiskModelCategory.ACLCheck)]
	[RuleIntroducedIn(2,7)]
	[RuleComputation(RuleComputationType.PerDiscover, 15)]
	[RuleANSSI("R18", "subsubsection.3.3.2")]
    [RuleMaturityLevel(2)]
	public class HealthCheckRulePrivilegedExchangePrivEsc : RuleBase<HealthCheckData>
    {
		protected override int? AnalyzeDataNew(HealthCheckData healthcheckData)
        {
			if (healthcheckData.ExchangePrivEscVulnerable)
				return 1;
			return 0;
        }
    }
}
