//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("S-Domain$$$", RiskRuleCategory.Trusts, RiskModelCategory.SIDHistory)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 5)]
    [RuleANSSI("R15", "paragraph.3.3.1.5")]
    [RuleMaturityLevel(3)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.PrivilegedAccountManagement)]
    public class HeatlcheckRuleTrustSIDHistoryAuditingGroup : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.SIDHistoryAuditingGroupPresent)
            {
                return 1;
            }
            return 0;
        }
    }
}
