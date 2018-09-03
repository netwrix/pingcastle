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
	[HeatlcheckRuleModel("A-NullSession", HealthcheckRiskRuleCategory.Anomalies, HealthcheckRiskModelCategory.Reconnaissance)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnPresence, 10)]
    public class HeatlcheckRuleAnomalyNullSession : HeatlcheckRuleBase
    {
		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.DomainControllers != null)
            {
                foreach (var DC in healthcheckData.DomainControllers)
                {
					if (DC.HasNullSession)
					{
						AddRawDetail(DC.DCName);
					}
                }
            }
            return null;
        }
    }
}
