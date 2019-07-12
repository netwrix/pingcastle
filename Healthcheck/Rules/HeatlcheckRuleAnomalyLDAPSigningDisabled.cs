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
	[RuleModel("A-LDAPSigningDisabled", RiskRuleCategory.Anomalies, RiskModelCategory.NetworkSniffing)]
	[RuleComputation(RuleComputationType.TriggerOnPresence, 5)]
	[RuleBSI("M 2.412")]
	[RuleCERTFR("CERTFR-2015-ACT-021", "SECTION00010000000000000000")]
	[RuleSTIG("V-3381", "The Recovery Console option is set to permit automatic logon to the system.", STIGFramework.Windows2008)]
	[RuleIntroducedIn(2, 7)]
	public class HeatlcheckRuleAnomalyLDAPSigningDisabled : RuleBase<HealthcheckData>
	{
		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
		{
			foreach (GPPSecurityPolicy policy in healthcheckData.GPOLsaPolicy)
			{
				foreach (GPPSecurityPolicyProperty property in policy.Properties)
				{
					if (property.Property == "LDAPClientIntegrity")
					{
						if (property.Value == 0)
						{
							AddRawDetail(policy.GPOName);
							break;
						}
					}
				}
			}
			return null;
		}
	}
}
