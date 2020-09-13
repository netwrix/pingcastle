//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//

using PingCastle.Rules;

namespace PingCastle.HealthCheck.Rules
{
	[RuleModel("P-RecycleBin", RiskRuleCategory.PrivilegedAccounts, RiskModelCategory.IrreversibleChange)]
	[RuleComputation(RuleComputationType.TriggerOnPresence, 10)]
	[RuleIntroducedIn(2, 7)]
    [RuleMaturityLevel(3)]
	public class HealthCheckRulePrivilegedRecycleBin : RuleBase<HealthCheckData>
	{
		protected override int? AnalyzeDataNew(HealthCheckData healthcheckData)
		{
			if (healthcheckData.IsRecycleBinEnabled)
			{
				return 0;
			}
			return 1;
		}
	}
}
