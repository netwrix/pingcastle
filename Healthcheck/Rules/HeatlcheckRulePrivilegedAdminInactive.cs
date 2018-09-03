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
	[HeatlcheckRuleModel("P-Inactive", HealthcheckRiskRuleCategory.PrivilegedAccounts, HealthcheckRiskModelCategory.AdminControl)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnThreshold, 30, Threshold: 30, Order: 1)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnThreshold, 20, Threshold: 15, Order: 2)]
    public class HeatlcheckRulePrivilegedAdminInactive : HeatlcheckRuleBase
    {
		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            
            int adminEnabledAndInactive = 0;
            if (healthcheckData.AllPrivilegedMembers.Count > 20)
            {
                foreach (var member in healthcheckData.AllPrivilegedMembers)
                {
                    if (member.IsEnabled && !member.IsActive)
                        adminEnabledAndInactive++;
                }
				return 100 * adminEnabledAndInactive / healthcheckData.AllPrivilegedMembers.Count;
            }
            return 0;
        }
    }
}
