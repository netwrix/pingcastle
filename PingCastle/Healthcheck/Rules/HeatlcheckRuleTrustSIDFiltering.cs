//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Data;
using PingCastle.Rules;
using System.Collections.Generic;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("T-SIDFiltering", RiskRuleCategory.Trusts, RiskModelCategory.SIDFiltering)]
    [RuleComputation(RuleComputationType.TriggerOnThreshold, 100, Threshold: 4, Order: 1)]
    [RuleComputation(RuleComputationType.TriggerOnThreshold, 80, Threshold: 2, Order: 2)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 50, Order: 3)]
    [RuleSTIG("V-8538", "Security identifiers (SIDs) must be configured to use only authentication data of directly trusted external or forest trust. ")]
    [RuleANSSI("R16", "paragraph.3.3.1.6")]
    //[RuleBSI("M 4.314")]
    [RuleDurANSSI(1, "trusts_forest_sidhistory", "Outbound forest trust relationships with sID History enabled")]
    [RuleDurANSSI(1, "trusts_domain_notfiltered", "Unfiltered outbound domain trust relationship")]
    [RuleMitreAttackMitigation(MitreAttackMitigation.ActiveDirectoryConfiguration)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.AccessTokenManipulationSIDHistoryInjection)]
    public class HeatlcheckRuleTrustSIDFiltering : RuleBase<HealthcheckData>
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
