//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.Text;

namespace PingCastle.Healthcheck.Rules
{
	[HeatlcheckRuleModel("A-NoServicePolicy", HealthcheckRiskRuleCategory.Anomalies, HealthcheckRiskModelCategory.WeakPassword)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnPresence, 0)]
    public class HeatlcheckRuleAnomalyServicePolicy : HeatlcheckRuleBase
    {
		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            bool servicePolicy = false;
            foreach (GPPSecurityPolicy policy in healthcheckData.GPPPasswordPolicy)
            {
                foreach (GPPSecurityPolicyProperty property in policy.Properties)
                {
                    if (!servicePolicy && property.Property == "MinimumPasswordLength")
                    {
                        if (property.Value >= 20)
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
