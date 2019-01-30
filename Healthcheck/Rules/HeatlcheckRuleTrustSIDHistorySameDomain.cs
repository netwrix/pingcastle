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
	[RuleModel("T-SIDHistorySameDomain", RiskRuleCategory.Trusts, RiskModelCategory.SIDHistory)]
	[RuleComputation(RuleComputationType.TriggerOnPresence, 50)]
	[RuleANSSI("R15", "paragraph.3.3.1.5")]
    public class HeatlcheckRuleTrustSIDHistorySameDomain : RuleBase<HealthcheckData>
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
