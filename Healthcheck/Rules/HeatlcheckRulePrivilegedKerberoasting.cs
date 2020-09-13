//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.Text;
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
	[RuleModel("P-Kerberoasting", RiskRuleCategory.PrivilegedAccounts, RiskModelCategory.AccountTakeOver)]
	[RuleComputation(RuleComputationType.PerDiscover, 5)]
	[RuleIntroducedIn(2, 7)]
    [RuleDurANSSI(1, "spn_priv", "Privileged accounts with SPN")]
	public class HeatlcheckRulePrivilegedKerberoasting : RuleBase<HealthcheckData>
    {
		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
			var dangerousGroups = new List<string>() {
				"Domain Admins",
				"Enterprise Admins",
				"Schema Admins",
				"Administrators"
            };
			foreach (var group in healthcheckData.PrivilegedGroups)
			{
				if (!dangerousGroups.Contains(group.GroupName))
				{
					continue;
				}
				foreach (var user in group.Members)
				{
					if (user.IsService && user.PwdLastSet.AddDays(40) < DateTime.Now)
					{
						AddRawDetail(group.GroupName, user.Name);
					}
				}
			}
            return null;
        }
    }
}
