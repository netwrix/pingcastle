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
    [RuleModel("S-WSUS-UserProxy", RiskRuleCategory.StaleObjects, RiskModelCategory.VulnerabilityManagement)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 1)]
    [RuleMaturityLevel(2)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.UpdateSoftware)]
    [RuleIntroducedIn(2, 10, 1)]
    public class HeatlcheckRuleStaledWSUSUserProxy : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.GPOWSUS != null && healthcheckData.GPOWSUS.Count > 0)
            {
                bool foundHttp = false;
                foreach (var gpo in healthcheckData.GPOWSUS)
                {
                    if (!string.IsNullOrEmpty(gpo.WSUSserver))
                    {
                        Uri uri;
                        if (Uri.TryCreate(gpo.WSUSserver, UriKind.Absolute, out uri))
                        {
                            if (uri.Scheme == "http")
                            {
                                foundHttp = true;
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
                                foundHttp = true;
                            }
                        }
                    }
                }
                if (foundHttp)
                {
                    foreach (var gpo in healthcheckData.GPOWSUS)
                    {
                        if (gpo.Options != null)
                        {
                            foreach (var o in gpo.Options)
                            {
                                if (o.Name == "SetProxyBehaviorForUpdateDetection" && o.Value != 0)
                                {
                                    AddRawDetail(gpo.GPOName);
                                }
                            }
                        }
                    }
                }
            }
            return null;
        }
    }
}
