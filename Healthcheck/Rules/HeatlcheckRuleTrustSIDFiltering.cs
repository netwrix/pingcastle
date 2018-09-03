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
	[HeatlcheckRuleModel("T-SIDFiltering", HealthcheckRiskRuleCategory.Trusts, HealthcheckRiskModelCategory.SIDFiltering)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnThreshold, 100, Threshold: 4, Order: 1)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnThreshold, 80, Threshold: 2, Order: 2)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnPresence, 50, Order: 3)]
    [HeatlcheckRuleSTIG("V-8538")]
    public class HeatlcheckRuleTrustSIDFiltering : HeatlcheckRuleBase
    {
		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData, ICollection<DomainKey> AllowedMigrationDomains)
        {
            foreach (HealthCheckTrustData trust in healthcheckData.Trusts)
            {
                bool skip = false;
                if (AllowedMigrationDomains != null)
                {
                    foreach (DomainKey allowedDomain in AllowedMigrationDomains)
                    {
                        if (allowedDomain == trust.Domain)
                        {
                            skip = true;
                            break;
                        }
                        if (trust.KnownDomains != null)
                        {
                            foreach (HealthCheckTrustDomainInfoData kd in trust.KnownDomains)
                            {
                                if (kd.Domain == allowedDomain)
                                {
                                    skip = true;
                                    break;
                                }
                            }
                        }
                        if (skip)
                            break;
                    }
                }
                if (!skip && TrustAnalyzer.GetSIDFiltering(trust) == "No")
                {
                    AddRawDetail(trust.TrustPartner);
                }
            }
			return null;
        }
    }
}
