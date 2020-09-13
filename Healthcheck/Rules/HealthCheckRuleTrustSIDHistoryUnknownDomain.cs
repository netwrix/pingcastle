//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//

using System;
using System.Collections.Generic;
using PingCastle.Rules;

namespace PingCastle.HealthCheck.Rules
{
    [RuleModel("T-SIDHistoryUnknownDomain", RiskRuleCategory.Trusts, RiskModelCategory.SIDHistory)]
    [RuleComputation(RuleComputationType.PerDiscover, 10)]
    [RuleANSSI("R15", "paragraph.3.3.1.5")]
    [RuleDurANSSI(3, "sidhistory_present", "Accounts or groups with SID history set")]
    public class HealthCheckRuleTrustSIDHistoryUnknownDomain : RuleBase<HealthCheckData>
    {
        protected override int? AnalyzeDataNew(HealthCheckData healthcheckData)
        {
            Dictionary<string, int> domainList = new Dictionary<string, int>();
            if (healthcheckData.UserAccountData != null && healthcheckData.UserAccountData.ListDomainSidHistory != null
                                                        && healthcheckData.UserAccountData.ListDomainSidHistory.Count > 0)
            {
                foreach (HealthCheckSIDHistoryData data in healthcheckData.UserAccountData.ListDomainSidHistory)
                {
                    if (data.FriendlyName.StartsWith("S-1-5-21", StringComparison.InvariantCultureIgnoreCase))
                    {
                        if (!domainList.ContainsKey(data.DomainSid))
                            domainList.Add(data.DomainSid, data.Count);
                        else
                            domainList[data.DomainSid] += data.Count;
                    }
                }
            }
            if (healthcheckData.ComputerAccountData != null && healthcheckData.ComputerAccountData.ListDomainSidHistory != null
                                                            && healthcheckData.ComputerAccountData.ListDomainSidHistory.Count > 0)
            {
                foreach (HealthCheckSIDHistoryData data in healthcheckData.ComputerAccountData.ListDomainSidHistory)
                {
                    if (data.FriendlyName.StartsWith("S-1-5-21", StringComparison.InvariantCultureIgnoreCase))
                    {
                        if (!domainList.ContainsKey(data.DomainSid))
                            domainList.Add(data.DomainSid, data.Count);
                        else
                            domainList[data.DomainSid] += data.Count;
                    }
                }
            }
            if (domainList.Count > 0)
            {
                foreach (string domain in domainList.Keys)
                {
                    AddRawDetail(domain, domainList[domain]);
                }
            }
            return null;
        }
    }
}