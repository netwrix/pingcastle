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
	[RuleModel("A-NoGPOLLMNR", RiskRuleCategory.Anomalies, RiskModelCategory.NetworkSniffing)]
	[RuleComputation(RuleComputationType.TriggerOnPresence, 0)]
	[RuleIntroducedIn(2, 7)]
	public class HeatlcheckRuleAnomalyNoGPOLLMNR : RuleBase<HealthcheckData>
	{
		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
		{
			bool found = false;
			foreach (GPPSecurityPolicy policy in healthcheckData.GPOLsaPolicy)
			{
				foreach (GPPSecurityPolicyProperty property in policy.Properties)
				{
					if (property.Property == "EnableMulticast")
					{
						found = true;
						if (property.Value == 1)
						{
							AddRawDetail(policy.GPOName);
						}
					}
				}
			}
			if (!found)
				return 1;
			return null;
		}
	}
}
