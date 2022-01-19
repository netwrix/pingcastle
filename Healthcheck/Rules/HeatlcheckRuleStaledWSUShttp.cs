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
    [RuleModel("S-WSUS-HTTP", RiskRuleCategory.StaleObjects, RiskModelCategory.VulnerabilityManagement)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 5)]
    [RuleMaturityLevel(2)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.UpdateSoftware)]
    [RuleIntroducedIn(2, 10, 1)]
    public class HeatlcheckRuleStaledWSUShttp : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.GPOWSUS != null && healthcheckData.GPOWSUS.Count > 0)
            {
                foreach (var gpo in healthcheckData.GPOWSUS)
                {
                    if (!string.IsNullOrEmpty(gpo.WSUSserver))
                    {
                        Uri uri;
                        if (Uri.TryCreate(gpo.WSUSserver, UriKind.Absolute, out uri))
                        {
                            if (uri.Scheme == "http")
                            {
                                AddRawDetail(gpo.GPOName, gpo.WSUSserver);
                            }
                        }
                    }
                    if (!string.IsNullOrEmpty(gpo.WSUSserverAlternate))
                    {
                        Uri uri;
                        if (Uri.TryCreate(gpo.WSUSserverAlternate, UriKind.Absolute, out uri))
                        {
                            if (uri.Scheme == "http")
                            {
                                AddRawDetail(gpo.GPOName, gpo.WSUSserverAlternate);
                            }
                        }
                    }
                }
            }
            return null;
        }
    }
}
