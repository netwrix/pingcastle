//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("S-WSUS-NoPinning", RiskRuleCategory.StaleObjects, RiskModelCategory.VulnerabilityManagement)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 2)]
    [RuleMaturityLevel(2)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.UpdateSoftware)]
    [RuleIntroducedIn(2, 10, 1)]
    public class HeatlcheckRuleStaledWSUSNoPinning : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.GPOWSUS != null && healthcheckData.GPOWSUS.Count > 0)
            {
                foreach (var gpo in healthcheckData.GPOWSUS)
                {
                    if (gpo.Options != null)
                    {
                        foreach (var o in gpo.Options)
                        {
                            if (o.Name == "DoNotEnforceEnterpriseTLSCertPinningForUpdateDetection" && o.Value != 0)
                            {
                                AddRawDetail(gpo.GPOName);
                            }
                        }
                    }
                }
            }
            return null;
        }
    }
}
