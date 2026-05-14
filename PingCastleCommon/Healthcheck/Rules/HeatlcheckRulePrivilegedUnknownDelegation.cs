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
    [RuleModel("P-UnkownDelegation", RiskRuleCategory.PrivilegedAccounts, RiskModelCategory.DelegationCheck)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 15)]
    [RuleMaturityLevel(4)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.ForcedAuthentication)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.ActiveDirectoryConfiguration)]
    [RuleSTIG("V-205741", "Windows Server 2019 Active Directory Group Policy objects must have proper access control permissions.", STIGFramework.WindowsServer2019)]
    public class HeatlcheckRulePrivilegedUnknownDelegation : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            foreach (HealthcheckDelegationData delegation in healthcheckData.Delegations)
            {
                if (delegation.Account.StartsWith("S-1-", StringComparison.InvariantCultureIgnoreCase))
                {
                    var sidpart = delegation.Account.Split('-');
                    // ignore well known admin group
                    if (int.Parse(sidpart[sidpart.Length - 1]) < 1000)
                        continue;
                    AddRawDetail(delegation.DistinguishedName, delegation.Account, delegation.Right);
                }
            }
            return null;
        }
    }
}
