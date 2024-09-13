using PingCastle.Report;
//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("S-FunctionalLevel1", RiskRuleCategory.StaleObjects, RiskModelCategory.ObsoleteOS)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 5)]
    [RuleDurANSSI(1, "functional_level", "Insufficient forest and domains functional levels")]
    [RuleIntroducedIn(2, 11, 2)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.UpdateSoftware)]
    public class HeatlcheckRuleStaledObsoleteFunctionalLevel1 : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.DomainFunctionalLevel < 4)
            {
                AddRawDetail("Domain", ReportHelper.DecodeDomainFunctionalLevel(healthcheckData.DomainFunctionalLevel));
            }
            if (healthcheckData.ForestFunctionalLevel < 4)
            {
                AddRawDetail("Forest", ReportHelper.DecodeForestFunctionalLevel(healthcheckData.ForestFunctionalLevel));
            }
            return null;
        }
    }
}
