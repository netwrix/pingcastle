//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;
using System;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("P-DNSDelegation", RiskRuleCategory.PrivilegedAccounts, RiskModelCategory.ACLCheck)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 0)]
    [RuleIntroducedIn(2, 8)]
    [RuleMaturityLevel(1)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.PrivilegedAccountManagement)]
    public class HeatlcheckRulePrivilegedDNSDelegation : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            /*
            foreach (HealthcheckDelegationData delegation in healthcheckData.Delegations)
            {
                if (delegation.DistinguishedName.StartsWith("CN=MicrosoftDNS,CN=System,DC="))
                {
                    //if (delegation.Account.StartsWith("NT AUTHORITY\\", StringComparison.InvariantCultureIgnoreCase))
                    //    continue;
                    if (delegation.SecurityIdentifier == "S-1-5-9")
                        continue;
                    if (delegation.Account.EndsWith("\\DnsAdmins", StringComparison.InvariantCultureIgnoreCase))
                        continue;
                    if (delegation.Right.Contains("Write all prop"))
                    {
                        AddRawDetail(delegation.Account, delegation.Right);
                    }
                }
            }
            */
            return null;
        }
    }
}
