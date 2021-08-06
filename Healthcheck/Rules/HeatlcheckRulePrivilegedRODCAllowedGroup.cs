//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("P-RODCAllowedGroup", RiskRuleCategory.PrivilegedAccounts, RiskModelCategory.RODC)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 5)]
    [RuleIntroducedIn(2, 9)]
    [RuleDurANSSI(3, "rodc_allowed_group", "Dangerous configuration of replication groups for read-only domain controllers (RODCs) (allow)")]
    [RuleMitreAttackMitigation(MitreAttackMitigation.ActiveDirectoryConfiguration)]
    public class HeatlcheckRulePrivilegedRODCAllowedGroup : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.DomainFunctionalLevel < 3)
                return 0;
            foreach (var member in healthcheckData.AllowedRODCPasswordReplicationGroup)
            {
                AddRawDetail(member);
            }
            return null;
        }
    }
}
