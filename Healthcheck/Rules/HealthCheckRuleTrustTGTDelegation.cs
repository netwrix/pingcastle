//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//

using System.Collections.Generic;
using PingCastle.Data;
using PingCastle.Rules;

namespace PingCastle.HealthCheck.Rules
{
    [RuleModel("T-TGTDelegation", RiskRuleCategory.Trusts, RiskModelCategory.TrustImpermeability)]
    [RuleComputation(RuleComputationType.PerDiscover, 10)]
    [RuleIntroducedIn(2, 7)]
    [RuleDurANSSI(3, "trusts_tgt_deleg", "Inbound trust relationships with delegation")]
    public class HealthCheckRuleTrustTGTDelegation : RuleBase<HealthCheckData>
    {
        protected override int? AnalyzeDataNew(HealthCheckData healthcheckData, ICollection<DomainKey> AllowedMigrationDomains)
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
                if (!skip && TrustAnalyzer.GetTGTDelegation(trust) == "Yes")
                {
                    AddRawDetail(trust.TrustPartner);
                }
            }
            return null;
        }
    }
}