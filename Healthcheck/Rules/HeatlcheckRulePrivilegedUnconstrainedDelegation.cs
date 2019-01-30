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
	[RuleModel("P-UnconstrainedDelegation", RiskRuleCategory.PrivilegedAccounts, RiskModelCategory.ACLCheck)]
	[RuleComputation(RuleComputationType.PerDiscover, 5)]
	[RuleANSSI("R18", "subsubsection.3.3.2")]
    public class HeatlcheckRulePrivilegedUnconstrainedDelegation : RuleBase<HealthcheckData>
    {
		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
			if (healthcheckData.UserAccountData.ListTrustedToAuthenticateForDelegation != null)
			{
				foreach (var delegation in healthcheckData.UserAccountData.ListTrustedToAuthenticateForDelegation)
				{
					AddRawDetail(delegation.DistinguishedName, delegation.Name);
				}
			}
			if (healthcheckData.ComputerAccountData.ListTrustedToAuthenticateForDelegation != null)
			{
				foreach (var delegation in healthcheckData.ComputerAccountData.ListTrustedToAuthenticateForDelegation)
				{
					bool found = false;
					foreach (var dc in healthcheckData.DomainControllers)
					{
						if (dc.DistinguishedName == delegation.DistinguishedName)
						{
							found = true;
							break;
						}
					}
					if (!found)
						AddRawDetail(delegation.DistinguishedName, delegation.Name);
				}
			}
			return null;
        }
    }
}
