//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-DnsZoneUpdate2", RiskRuleCategory.Anomalies, RiskModelCategory.NetworkSniffing)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 1)]
    [RuleIntroducedIn(2, 9)]
    [RuleDurANSSI(3, "dnszone_bad_prop", "Misconfigured DNS zones")]
    [RuleMitreAttackTechnique(MitreAttackTechnique.ManintheMiddle)]
    public class HeatlcheckRuleAnomalyDnsZoneUnsecureUpdate2 : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.DnsZones != null)
            {
                foreach (var zone in healthcheckData.DnsZones)
                {
                    if (!zone.InsecureUpdate)
                        continue;

                    if (!(zone.name == healthcheckData.DomainFQDN || zone.name == "RootDNSServers" || zone.name.StartsWith("_msdcs.")))
                    {
                        AddRawDetail(zone.name, healthcheckData.DomainFQDN, zone.DistinguishedName ?? "N/A", zone.Partition ?? "N/A");
                    }
                }
            }

            return null;
        }
    }
}
