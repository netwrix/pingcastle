//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//

using PingCastle.Rules;

namespace PingCastle.HealthCheck.Rules
{
	[RuleModel("T-Inactive", RiskRuleCategory.Trusts, RiskModelCategory.TrustInactive)]
	[RuleComputation(RuleComputationType.TriggerOnPresence, 20)]
    [RuleDurANSSI(2, "trusts_accounts", "Trust account passwords unchanged for more than a year")]
    public class HealthCheckRuleTrustInactive : RuleBase<HealthCheckData>
    {
		protected override int? AnalyzeDataNew(HealthCheckData healthcheckData)
        {
            foreach (HealthCheckTrustData trust in healthcheckData.Trusts)
            {
                if (!trust.IsActive)
                {
                    AddRawDetail(trust.TrustPartner);
                }
            }
            return null;
        }
    }
}
