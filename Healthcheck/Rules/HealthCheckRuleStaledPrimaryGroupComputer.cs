//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//

using PingCastle.Rules;

namespace PingCastle.HealthCheck.Rules
{
	[RuleModel("S-C-PrimaryGroup", RiskRuleCategory.StaleObjects, RiskModelCategory.ObjectConfig)]
	[RuleComputation(RuleComputationType.TriggerOnPresence, 15)]
    [RuleDurANSSI(3, "primary_group_id_nochange", "Accounts with modified PrimaryGroupID")]
    public class HealthCheckRuleStaledPrimaryGroupComputer : RuleBase<HealthCheckData>
    {
		protected override int? AnalyzeDataNew(HealthCheckData healthcheckData)
        {
			return healthcheckData.ComputerAccountData.NumberBadPrimaryGroup;
        }
    }
}
