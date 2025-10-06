//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;
using System;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("S-Vuln-MS14-068", RiskRuleCategory.StaleObjects, RiskModelCategory.VulnerabilityManagement)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 100)]
    [RuleCERTFR("CERTFR-2014-ALE-011")]
    [RuleMaturityLevel(1)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.UpdateSoftware)]
    public class HeatlcheckRuleStaledMS14_068 : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            DateTime alertDate = new DateTime(2014, 11, 18);
            if (healthcheckData.DomainControllers != null && healthcheckData.DomainControllers.Count > 0)
            {
                foreach (var DC in healthcheckData.DomainControllers)
                {
                    if (DC.StartupTime != DateTime.MinValue)
                    {
                        if (DC.StartupTime < alertDate)
                        {
                            AddRawDetail(DC.DCName, "StartupTime=" + DC.StartupTime);
                        }
                    }
                }
            }
            return null;
        }
    }
}
