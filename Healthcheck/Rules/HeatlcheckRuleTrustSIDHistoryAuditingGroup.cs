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
	[HeatlcheckRuleModel("S-Domain$$$", HealthcheckRiskRuleCategory.Trusts, HealthcheckRiskModelCategory.SIDHistory)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnPresence, 5)]
    public class HeatlcheckRuleTrustSIDHistoryAuditingGroup : HeatlcheckRuleBase
    {
		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.SIDHistoryAuditingGroupPresent)
            {
                return 1;
            }
            return 0;
        }
    }
}
