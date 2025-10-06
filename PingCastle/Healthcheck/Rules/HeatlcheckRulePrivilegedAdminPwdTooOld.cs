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
    [RuleModel("P-AdminPwdTooOld", RiskRuleCategory.PrivilegedAccounts, RiskModelCategory.AccountTakeOver)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 10)]
    [RuleIntroducedIn(2, 9)]
    [RuleDurANSSI(1, "password_change_priv", "Privileged account passwords age too old")]
    [RuleMitreAttackMitigation(MitreAttackMitigation.PrivilegedAccountManagement)]
    public class HeatlcheckRulePrivilegedAdminPwdTooOld : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            var users = new Dictionary<string, HealthCheckGroupMemberData>();
            foreach (var group in healthcheckData.PrivilegedGroups)
            {
                foreach (var user in group.Members)
                {
                    if (user.IsExternal)
                        continue;
                    if (!user.IsEnabled)
                        continue;
                    if (user.Created.AddDays(3 * 365) < DateTime.Now && user.PwdLastSet.AddDays(3 * 365) < DateTime.Now)
                    {
                        if (!users.ContainsKey(user.DistinguishedName))
                            users[user.DistinguishedName] = user;
                    }
                }
            }
            foreach (var user in users.Values)
                AddRawDetail(user.Name, user.Created.ToString("u"), user.PwdLastSet <= DateTime.Parse("1601-01-01 01:00:00Z") ? "Never" : user.PwdLastSet.ToString("u"));
            return null;
        }
    }
}
