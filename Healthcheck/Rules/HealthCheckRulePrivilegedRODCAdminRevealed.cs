//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//

using PingCastle.Rules;

namespace PingCastle.HealthCheck.Rules
{
    [RuleModel("P-RODCAdminRevealed", RiskRuleCategory.PrivilegedAccounts, RiskModelCategory.RODC)]
    [RuleComputation(RuleComputationType.PerDiscover, 5)]
    [RuleIntroducedIn(2, 9)]
    [RuleDurANSSI(2, "rodc_priv_revealed", "Privileged users revealed on RODC")]
    public class HealthCheckRulePrivilegedRODCAdminRevealed : RuleBase<HealthCheckData>
    {
        protected override int? AnalyzeDataNew(HealthCheckData healthcheckData)
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