//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-DnsZoneAUCreateChild", RiskRuleCategory.Anomalies, RiskModelCategory.NetworkSniffing)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 0)]
    [RuleIntroducedIn(2, 10, 1)]
    [RuleMaturityLevel(4)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.ManintheMiddle)]
    public class HeatlcheckRuleAnomalyDnsZoneAUCreateChild : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.DnsZones != null)
            {
                foreach (var zone in healthcheckData.DnsZones)
                {
                    if (zone.AUCreateChild)
                    {
                        AddRawDetail(zone.name);
                    }
                }
            }
            return null;
        }
    }
}
