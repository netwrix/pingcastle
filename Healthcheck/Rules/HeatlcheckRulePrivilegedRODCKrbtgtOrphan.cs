//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("P-RODCKrbtgtOrphan", RiskRuleCategory.PrivilegedAccounts, RiskModelCategory.RODC)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 1)]
    [RuleIntroducedIn(3, 3)]
    [RuleDurANSSI(3, "rodc_orphan_krbtgt", "Orphan RODC krbtgt accounts")]
    [RuleMitreAttackMitigation(MitreAttackMitigation.ActiveDirectoryConfiguration)]
    public class HeatlcheckRulePrivilegedRODCKrbtgtOrphan : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.DomainFunctionalLevel < 3)
                return 0;
            if (healthcheckData.RODCKrbtgtOrphans != null)
            {
                foreach (var member in healthcheckData.RODCKrbtgtOrphans)
                {
                    AddRawDetail(member.DistinguishedName, member.CreationDate);
                }
            }
            return null;
        }
    }
}
