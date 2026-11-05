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
            var dangerousGroups = new List<string>()
            {
                GraphObjectReference.DomainAdministrators,
                GraphObjectReference.EnterpriseAdministrators,
                GraphObjectReference.SchemaAdministrators,
                GraphObjectReference.Administrators,
            };

            var userAggregation = new Dictionary<string, UserKerberoastingData>();

            foreach (var group in healthcheckData.PrivilegedGroups)
            {
                if (!dangerousGroups.Contains(group.GroupName))
                {
                    continue;
                }

                foreach (var user in group.Members)
                {
                    if (user == null)
                    {
                        continue;
                    }

                    if (user.IsService && user.PwdLastSet.AddDays(40) < DateTime.Now)
                    {
                        bool trap = false;
                        if (healthcheckData.ListHoneyPot != null)
                        {
                            foreach (var account in healthcheckData.ListHoneyPot)
                            {
                                if (account == null)
                                {
                                    continue;
                                }

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
                        {
                            if (!userAggregation.ContainsKey(user.Name))
                            {
                                userAggregation[user.Name] = new UserKerberoastingData
                                {
                                    UserName = user.Name,
                                    Groups = new List<string>(),
                                    ServicePrincipalNames = user.ServicePrincipalNames ?? new List<string>()
                                };
                            }

                            if (!userAggregation[user.Name].Groups.Contains(group.GroupName))
                            {
                                userAggregation[user.Name].Groups.Add(group.GroupName);
                            }
                        }
                    }
                }
            }

            foreach (var entry in userAggregation.Values)
            {
                var groups = string.Join("<br>", entry.Groups);
                var spns = string.Join("<br>", entry.ServicePrincipalNames);
                AddRawDetail(entry.UserName, groups, spns);
            }

            return null;
        }

        private class UserKerberoastingData
        {
            public string UserName { get; set; }

            public List<string> Groups { get; set; }

            public List<string> ServicePrincipalNames { get; set; }
        }
    }
}
