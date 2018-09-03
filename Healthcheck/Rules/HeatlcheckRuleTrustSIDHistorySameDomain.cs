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
	[HeatlcheckRuleModel("T-SIDHistorySameDomain", HealthcheckRiskRuleCategory.Trusts, HealthcheckRiskModelCategory.SIDHistory)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnPresence, 50)]
    public class HeatlcheckRuleTrustSIDHistorySameDomain : HeatlcheckRuleBase
    {
		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            int count = 0;
            if (healthcheckData.UserAccountData != null && healthcheckData.UserAccountData.ListDomainSidHistory != null
                && healthcheckData.UserAccountData.ListDomainSidHistory.Count > 0)
            {
                foreach (HealthcheckSIDHistoryData data in healthcheckData.UserAccountData.ListDomainSidHistory)
                {
                    if (data.DomainSid == healthcheckData.DomainSid)
                    {
                        count += data.Count;
                    }
                }
            }
            if (healthcheckData.ComputerAccountData != null && healthcheckData.ComputerAccountData.ListDomainSidHistory != null
                && healthcheckData.ComputerAccountData.ListDomainSidHistory.Count > 0)
            {
                foreach (HealthcheckSIDHistoryData data in healthcheckData.ComputerAccountData.ListDomainSidHistory)
                {
                    if (data.DomainSid == healthcheckData.DomainSid)
                    {
                        count += data.Count;
                    }
                }
            }
			return count;
        }
    }
}
