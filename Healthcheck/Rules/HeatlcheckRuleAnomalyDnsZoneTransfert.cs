//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-DnsZoneTransfert", RiskRuleCategory.Anomalies, RiskModelCategory.Reconnaissance)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 5)]
    [RuleIntroducedIn(2, 9, 3)]
    [RuleMaturityLevel(2)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.RemoteSystemDiscovery)]
    public class HeatlcheckRuleAnomalyDnsZoneTransfert : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.DnsZones != null)
            {
                foreach (var zone in healthcheckData.DnsZones)
                {
                    if (!zone.ZoneTransfert)
                        continue;
                    AddRawDetail(zone.name);
                }
            }
            return null;
        }
    }
}
