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
    [RuleModel("A-HardenedPaths", RiskRuleCategory.Anomalies, RiskModelCategory.NetworkSniffing)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 5)]
    [RuleSTIG("V-63577", "Hardened UNC Paths must be defined to require mutual authentication and integrity for at least the \\\\*\\SYSVOL and \\\\*\\NETLOGON shares.", STIGFramework.Windows10)]
    [RuleMaturityLevel(2)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.ManintheMiddleLLMNRNBTNSPoisoningandSMBRelay)]
    [RuleIntroducedIn(2,10,1)]
    public class HeatlcheckRuleAnomalyHardenedPaths : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.GPOHardenedPath == null)
                return null;
            foreach (var policy in healthcheckData.GPOHardenedPath)
            {
                if (policy.RequireIntegrity == false || policy.RequireMutualAuthentication == false)
                {
                    bool anomaly = false;
                    if (policy.Key.IndexOf("SYSVOL", StringComparison.OrdinalIgnoreCase) > 0 || policy.Key.IndexOf("NETLOGON", StringComparison.OrdinalIgnoreCase) > 0)
                    {
                        anomaly = true;
                    }
                    else
                    {
                        foreach (var dc in healthcheckData.DomainControllers)
                        {
                            if (policy.Key.StartsWith("\\\\" + dc.DCName + "\\", StringComparison.OrdinalIgnoreCase) && policy.Key.Contains("*"))
                            {
                                anomaly = true;
                            }
                        }
                    }
                    if (anomaly)
                    {
                        AddRawDetail(policy.GPOName, policy.Key, GetString(policy.RequireIntegrity), GetString(policy.RequireMutualAuthentication), GetString(policy.RequirePrivacy));
                    }
                }
            }
            return null;
        }

        private static string GetString(bool? data)
        {
            if (data == null)
                return "Not Set";
            if ((bool)data)
                return "Enabled";
            else
                return "Disabled";
        }
    }
}
