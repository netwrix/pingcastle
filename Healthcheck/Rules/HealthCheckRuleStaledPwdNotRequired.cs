//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//

using PingCastle.Rules;

namespace PingCastle.HealthCheck.Rules
{
	[RuleModel("S-PwdNotRequired", RiskRuleCategory.StaleObjects, RiskModelCategory.ObjectConfig)]
	[RuleComputation(RuleComputationType.TriggerOnPresence, 15)]
	[RuleANSSI("R36", "subsection.3.6")]
    [RuleMaturityLevel(3)]
    public class HealthCheckRuleStaledPwdNotRequired : RuleBase<HealthCheckData>
    {
		protected override int? AnalyzeDataNew(HealthCheckData healthcheckData)
        {
			return healthcheckData.UserAccountData.NumberPwdNotRequired;
        }
    }
}
