//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//

using PingCastle.Rules;

namespace PingCastle.HealthCheck.Rules
{
	[RuleModel("S-Domain$$$", RiskRuleCategory.Trusts, RiskModelCategory.SIDHistory)]
	[RuleComputation(RuleComputationType.TriggerOnPresence, 5)]
	[RuleANSSI("R15", "paragraph.3.3.1.5")]
    [RuleMaturityLevel(3)]
    public class HealthCheckRuleTrustSIDHistoryAuditingGroup : RuleBase<HealthCheckData>
    {
		protected override int? AnalyzeDataNew(HealthCheckData healthcheckData)
        {
            if (healthcheckData.SIDHistoryAuditingGroupPresent)
            {
                return 1;
            }
            return 0;
        }
    }
}
