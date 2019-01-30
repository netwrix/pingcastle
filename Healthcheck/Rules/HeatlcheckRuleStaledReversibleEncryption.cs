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
	[RuleModel("S-Reversible", RiskRuleCategory.StaleObjects, RiskModelCategory.ObjectConfig)]
	[RuleComputation(RuleComputationType.TriggerOnPresence, 5)]
    public class HeatlcheckRuleStaledReversibleEncryption : RuleBase<HealthcheckData>
    {
		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
			return healthcheckData.UserAccountData.NumberReversibleEncryption;
        }
    }
}
