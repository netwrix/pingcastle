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
	[RuleModel("P-AdminNum", RiskRuleCategory.PrivilegedAccounts, RiskModelCategory.AdminControl)]
	[RuleComputation(RuleComputationType.TriggerOnThreshold, 10, Threshold: 10)]
	[RuleANSSI("R26", "subsection.3.5")]
	[RuleANSSI("R30", "subsubsection.3.5.7")]
    public class HeatlcheckRulePrivilegedAdminNumber : RuleBase<HealthcheckData>
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
