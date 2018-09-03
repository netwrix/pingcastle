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
	[HeatlcheckRuleModel("T-Inactive", HealthcheckRiskRuleCategory.Trusts, HealthcheckRiskModelCategory.TrustInactive)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnPresence, 20)]
    public class HeatlcheckRuleTrustInactive : HeatlcheckRuleBase
    {
		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            foreach (HealthCheckTrustData trust in healthcheckData.Trusts)
            {
                if (!trust.IsActive)
                {
                    AddRawDetail(trust.TrustPartner);
                }
            }
            return null;
        }
    }
}
