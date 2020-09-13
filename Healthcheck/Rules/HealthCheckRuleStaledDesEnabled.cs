//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//

using PingCastle.Rules;

namespace PingCastle.HealthCheck.Rules
{
	[RuleModel("S-DesEnabled", RiskRuleCategory.StaleObjects, RiskModelCategory.OldAuthenticationProtocols)]
	[RuleComputation(RuleComputationType.TriggerOnPresence, 15)]
    [RuleDurANSSI(2, "kerberos_properties_deskey", "Use of Kerberos with weak encryption")]
    public class HealthCheckRuleStaledDesEnabled : RuleBase<HealthCheckData>
    {
		protected override int? AnalyzeDataNew(HealthCheckData healthcheckData)
        {
			return healthcheckData.UserAccountData.NumberDesEnabled + healthcheckData.ComputerAccountData.NumberDesEnabled;
        }
    }
}
