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
	[HeatlcheckRuleModel("A-ProtectedUsers", HealthcheckRiskRuleCategory.Anomalies, HealthcheckRiskModelCategory.PassTheCredential)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnPresence, 0)]
    [HeatlcheckRuleSTIG("V-78131")]
    public class HeatlcheckRuleAnomalySchemaProtectedUsers : HeatlcheckRuleBase
    {
		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
			if (healthcheckData.SchemaVersion < 69)
				return 1;
			return 0;
        }
    }
}
