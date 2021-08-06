//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-Krbtgt", RiskRuleCategory.Anomalies, RiskModelCategory.GoldenTicket)]
    [RuleComputation(RuleComputationType.TriggerOnThreshold, 50, Threshold: 1464, Order: 1)]
    [RuleComputation(RuleComputationType.TriggerOnThreshold, 40, Threshold: 1098, Order: 2)]
    [RuleComputation(RuleComputationType.TriggerOnThreshold, 30, Threshold: 732, Order: 3)]
    [RuleComputation(RuleComputationType.TriggerOnThreshold, 20, Threshold: 366, Order: 4)]
    [RuleCERTFR("CERTFR-2014-ACT-032", "SECTION00030000000000000000")]
    [RuleDurANSSI(2, "krbtgt", "Krbtgt account password unchanged for more than a year")]
    [RuleMitreAttackTechnique(MitreAttackTechnique.StealorForgeKerberosTicketsGoldenTicket)]
    public class HeatlcheckRuleAnomalyKrbtgt : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            return (int)(healthcheckData.GenerationDate - healthcheckData.KrbtgtLastChangeDate).TotalDays;
        }
    }
}
