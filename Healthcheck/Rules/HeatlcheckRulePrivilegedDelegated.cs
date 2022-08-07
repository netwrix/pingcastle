//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("P-Delegated", RiskRuleCategory.PrivilegedAccounts, RiskModelCategory.AccountTakeOver)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 20)]
    [RuleSTIG("V-36435", "Delegation of privileged accounts must be prohibited.")]
    [RuleMaturityLevel(3)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.ActiveDirectoryConfiguration)]
    public class HeatlcheckRulePrivilegedDelegated : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            int adminCanBeDelegated = 0;
            foreach (var member in healthcheckData.AllPrivilegedMembers)
            {
                if (member.CanBeDelegated)
                {
                    bool trap = false;
                    if (healthcheckData.ListHoneyPot != null)
                    {
                        foreach (var account in healthcheckData.ListHoneyPot)
                        {
                            if (account == null)
                                continue;
                            if (account.Name == member.Name || account.Name + "$" == member.Name)
                            {
                                trap = true;
                                break;
                            }
                            if (account.DistinguishedName == member.DistinguishedName)
                            {
                                trap = true;
                                break;
                            }
                        }
                    }
                    if (trap)
                        continue;
                    if (healthcheckData.SchemaVersion < 69)
                    {
                        adminCanBeDelegated++;
                    }
                    else if (!member.IsInProtectedUser)
                    {
                        adminCanBeDelegated++;  
                    }
                }
            }
            return adminCanBeDelegated;
        }
    }
}
