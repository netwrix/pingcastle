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
	[HeatlcheckRuleModel("P-AdminNum", HealthcheckRiskRuleCategory.PrivilegedAccounts, HealthcheckRiskModelCategory.AdminControl)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnThreshold, 10, Threshold: 10)]
    public class HeatlcheckRulePrivilegedAdminNumber : HeatlcheckRuleBase
    {
		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
			if (healthcheckData.UserAccountData.NumberActive <= 100)
				return 0;
			if (healthcheckData.AllPrivilegedMembers.Count == 0)
				return 0;
			return healthcheckData.AllPrivilegedMembers.Count * 100 / healthcheckData.UserAccountData.NumberActive;
        }
    }
}
