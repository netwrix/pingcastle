//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//

using PingCastle.Rules;

namespace PingCastle.HealthCheck.Rules
{
	[RuleModel("P-DsHeuristicsAdminSDExMask", RiskRuleCategory.PrivilegedAccounts, RiskModelCategory.ACLCheck)]
	[RuleComputation(RuleComputationType.TriggerOnPresence, 5)]
	[RuleIntroducedIn(2,7)]
    [RuleDurANSSI(1, "dsheuristics_bad", "Dangerous dsHeuristics settings")]
	public class HealthCheckRulePrivilegedDsHeuristicsAdminSDExMaskModified : RuleBase<HealthCheckData>
    {
		protected override int? AnalyzeDataNew(HealthCheckData healthcheckData)
        {
            if (healthcheckData.DsHeuristicsAdminSDExMaskModified)
            {
                return 1;
            }
            return 0;
        }
    }
}
