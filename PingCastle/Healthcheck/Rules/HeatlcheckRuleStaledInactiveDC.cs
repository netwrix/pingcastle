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
    [RuleModel("S-DC-Inactive", RiskRuleCategory.StaleObjects, RiskModelCategory.InactiveUserOrComputer)]
    [RuleComputation(RuleComputationType.PerDiscover, 5)]
    [RuleANSSI("R45", "paragraph.3.6.6.2")]
    [RuleDurANSSI(1, "password_change_inactive_dc", "Inactive domain controllers")]
    [RuleIntroducedIn(2, 9)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.UserAccountManagement)]
    public class HeatlcheckRuleStaledInactiveDC : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            foreach (var dc in healthcheckData.DomainControllers)
            {
                // Entra ID fake DC are not supposed to login and are then considered as inactive
                if (dc.AzureADKerberos)
                {
                    continue;
                }
                if (dc.LastComputerLogonDate < DateTime.Now.AddDays(-45))
                {
                    bool isException = false;
                    if (InfrastructureSettings != null && InfrastructureSettings.Riverbeds != null)
                    {
                        foreach (var riverbed in InfrastructureSettings.Riverbeds)
                        {
                            var test = riverbed.samAccountName;
                            if (test.EndsWith("$"))
                                test = test.Substring(0, test.Length - 1);
                            if (string.Equals(test, dc.DCName, StringComparison.OrdinalIgnoreCase))
                            {
                                isException = true;
                                break;
                            }
                        }
                    }
                    if (!isException)
                    {
                        AddRawDetail(dc.DCName, dc.LastComputerLogonDate.ToString("u"));
                    }
                }
            }
            return null;
        }
    }
}
