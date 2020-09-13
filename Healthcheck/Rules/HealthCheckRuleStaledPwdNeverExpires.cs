//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//

using PingCastle.Rules;

namespace PingCastle.HealthCheck.Rules
{
	[RuleModel("S-PwdNeverExpires", RiskRuleCategory.StaleObjects, RiskModelCategory.ObjectConfig)]
	[RuleComputation(RuleComputationType.TriggerOnPresence, 1)]
	[RuleIntroducedIn(2,9)]
    [RuleDurANSSI(2, "dont_expire", "Accounts with never-expiring passwords")]
    public class HealthCheckRuleStaledPwdNeverExpires : RuleBase<HealthCheckData>
    {
		protected override int? AnalyzeDataNew(HealthCheckData healthcheckData)
        {
			return healthcheckData.UserAccountData.NumberPwdNeverExpires;
        }
    }
}
