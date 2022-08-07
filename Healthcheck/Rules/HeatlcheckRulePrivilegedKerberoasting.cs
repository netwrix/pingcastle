using PingCastle.Graph.Reporting;
//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;
using System;
using System.Collections.Generic;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("P-Kerberoasting", RiskRuleCategory.PrivilegedAccounts, RiskModelCategory.AccountTakeOver)]
    [RuleComputation(RuleComputationType.PerDiscover, 5)]
    [RuleIntroducedIn(2, 7)]
    [RuleDurANSSI(1, "spn_priv", "Privileged accounts with SPN")]
    [RuleMitreAttackTechnique(MitreAttackTechnique.StealorForgeKerberosTicketsKerberoasting)]
    public class HeatlcheckRulePrivilegedKerberoasting : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            var dangerousGroups = new List<string>() {
                GraphObjectReference.DomainAdministrators,
                GraphObjectReference.EnterpriseAdministrators,
                GraphObjectReference.SchemaAdministrators,
                GraphObjectReference.Administrators,
            };
            foreach (var group in healthcheckData.PrivilegedGroups)
            {
                if (!dangerousGroups.Contains(group.GroupName))
                {
                    continue;
                }
                foreach (var user in group.Members)
                {
                    if (user == null)
                        continue;
                    if (user.IsService && user.PwdLastSet.AddDays(40) < DateTime.Now)
                    {
                        bool trap = false;
                        if (healthcheckData.ListHoneyPot != null)
                        {
                            foreach (var account in healthcheckData.ListHoneyPot)
                            {
                                if (account == null)
                                    continue;
                                if (account.Name == user.Name || account.Name + "$" == user.Name)
                                {
                                    trap = true;
                                    break;
                                }
                                if (account.DistinguishedName == user.DistinguishedName)
                                {
                                    trap = true;
                                    break;
                                }
                            }
                        }
                        if (!trap)
                            AddRawDetail(group.GroupName, user.Name);
                    }
                }
            }
            return null;
        }
    }
}
