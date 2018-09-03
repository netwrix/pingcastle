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
	[HeatlcheckRuleModel("A-MinPwdLen", HealthcheckRiskRuleCategory.Anomalies, HealthcheckRiskModelCategory.WeakPassword)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnPresence, 10)]
    public class HeatlcheckRuleAnomalyMinPasswordLen : HeatlcheckRuleBase
    {
		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            foreach (GPPSecurityPolicy policy in healthcheckData.GPPPasswordPolicy)
            {
                foreach (GPPSecurityPolicyProperty property in policy.Properties)
                {
                    if (property.Property == "MinimumPasswordLength")
                    {
                        if (property.Value < 8)
                        {
                            AddRawDetail(policy.GPOName);
                        }
                    }
                }
            }
            return null;
        }
    }
}
