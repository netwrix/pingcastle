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
	[RuleModel("A-MinPwdLen", RiskRuleCategory.Anomalies, RiskModelCategory.WeakPassword)]
	[RuleComputation(RuleComputationType.TriggerOnPresence, 10)]
	[RuleBSI("M 4.314")]
    public class HeatlcheckRuleAnomalyMinPasswordLen : RuleBase<HealthcheckData>
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
