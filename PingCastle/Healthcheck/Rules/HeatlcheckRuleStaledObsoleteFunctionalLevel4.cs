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
    [RuleModel("S-FunctionalLevel4", RiskRuleCategory.StaleObjects, RiskModelCategory.ObsoleteOS)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 0)]
    [RuleDurANSSI(3, "functional_level", "Insufficient forest and domains functional levels")]
    [RuleIntroducedIn(2, 11, 2)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.UpdateSoftware)]
    public class HeatlcheckRuleStaledObsoleteFunctionalLevel4 : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.DomainFunctionalLevel >= 6 && healthcheckData.DomainFunctionalLevel < 7)
            {
                AddRawDetail("Domain", ReportHelper.DecodeDomainFunctionalLevel(healthcheckData.DomainFunctionalLevel));
            }
            if (healthcheckData.ForestFunctionalLevel >= 6 && healthcheckData.ForestFunctionalLevel < 7)
            {
                AddRawDetail("Forest", ReportHelper.DecodeForestFunctionalLevel(healthcheckData.ForestFunctionalLevel));
            }
            return null;
        }
    }
}
