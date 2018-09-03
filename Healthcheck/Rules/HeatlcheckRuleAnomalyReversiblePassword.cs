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
	[HeatlcheckRuleModel("A-ReversiblePwd", HealthcheckRiskRuleCategory.Anomalies, HealthcheckRiskModelCategory.PasswordRetrieval)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnPresence, 10)]
    public class HeatlcheckRuleAnomalyReversiblePassword : HeatlcheckRuleBase
    {
		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            foreach (GPPSecurityPolicy policy in healthcheckData.GPPPasswordPolicy)
            {
                foreach (GPPSecurityPolicyProperty property in policy.Properties)
                {
                    if (property.Property == "ClearTextPassword")
                    {
                        if (property.Value > 0)
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
