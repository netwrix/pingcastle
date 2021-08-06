//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("P-RODCAdminRevealed", RiskRuleCategory.PrivilegedAccounts, RiskModelCategory.RODC)]
    [RuleComputation(RuleComputationType.PerDiscover, 5)]
    [RuleIntroducedIn(2, 9)]
    [RuleDurANSSI(2, "rodc_priv_revealed", "Privileged users revealed on RODC")]
    [RuleMitreAttackMitigation(MitreAttackMitigation.ActiveDirectoryConfiguration)]
    public class HeatlcheckRulePrivilegedRODCAdminRevealed : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.DomainFunctionalLevel < 3)
                return 0;

            foreach (var dc in healthcheckData.DomainControllers)
            {
                if (!dc.RODC)
                    continue;
                if (dc.msDSRevealedUsers != null)
                {
                    foreach (var account in dc.msDSRevealedUsers)
                    {
                        foreach (var admin in healthcheckData.AllPrivilegedMembers)
                        {
                            if (admin.DistinguishedName == account)
                            {
                                AddRawDetail(dc.DCName, account);
                            }
                        }
                    }
                }
            }
            return null;
        }
    }
}
