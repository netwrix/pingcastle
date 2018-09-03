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
	[HeatlcheckRuleModel("A-SmartCardRequired", HealthcheckRiskRuleCategory.Anomalies, HealthcheckRiskModelCategory.PassTheCredential)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnPresence, 30)]
    [HeatlcheckRuleSTIG("V-72821")]
    public class HeatlcheckRuleAnomalySmartCardRequired : HeatlcheckRuleBase
    {
		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
			return healthcheckData.SmartCardNotOK.Count;
        }
    }
}
