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
	[RuleModel("A-DsHeuristicsAnonymous", RiskRuleCategory.Anomalies, RiskModelCategory.Reconnaissance)]
	[RuleComputation(RuleComputationType.TriggerOnPresence, 5)]
	[RuleSTIG("V-8555", "Anonymous Access to AD forest data above the rootDSE level must be disabled. ", STIGFramework.Forest)]
    public class HeatlcheckRuleAnomalyDsHeuristicsAnonymous : RuleBase<HealthcheckData>
    {
		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.DsHeuristicsAnonymousAccess)
            {
                return 1;
            }
            return 0;
        }
    }
}
