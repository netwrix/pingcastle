//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-NTFRSOnSysvol", RiskRuleCategory.Anomalies, RiskModelCategory.NetworkSniffing)]
    [RuleComputation(RuleComputationType.TriggerOnThreshold, 5, Threshold: 2, Order: 1)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 0, Order: 2)]
    [RuleIntroducedIn(2, 9)]
    [RuleDurANSSI(2, "sysvol_ntfrs", "SYSVOL replication through NTFRS")]
    [RuleMitreAttackTechnique(MitreAttackTechnique.RemoteServiceSessionHijacking)]
    public class HeatlcheckRuleAnomalyNTFRSOnSYSVOL : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.UsingNTFRSForSYSVOL)
            {
                foreach (var DC in healthcheckData.DomainControllers)
                {
                    switch (DC.OperatingSystem)
                    {
                        case "Windows NT":
                        case "Windows 2000":
                        case "Windows 2003":
                        case "Windows 2008":
                        case "Windows 2012":
                        case "Windows 2016":
                            continue;
                    }
                    return 1;
                }
                return 2;
            }
            return 0;
        }
    }
}
