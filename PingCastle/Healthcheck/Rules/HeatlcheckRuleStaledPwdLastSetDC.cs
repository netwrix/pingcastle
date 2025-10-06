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
    [RuleModel("S-PwdLastSet-DC", RiskRuleCategory.StaleObjects, RiskModelCategory.InactiveUserOrComputer)]
    [RuleComputation(RuleComputationType.PerDiscover, 5)]
    [RuleDurANSSI(1, "password_change_dc_no_change", "Domain controllers with passwords unchanged for more than 45 days")]
    [RuleSTIG("V-63653", "The computer account password must not be prevented from being reset.", STIGFramework.Windows10)]
    [RuleSTIG("V-3373", "The maximum age for machine account passwords is not set to requirements.", STIGFramework.Windows7)]
    [RuleIntroducedIn(2, 9)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.ActiveDirectoryConfiguration)]
    public class HeatlcheckRuleStaledPwdLastSetDC : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            foreach (var dc in healthcheckData.DomainControllers)
            {
                // note: we ensure that the DC is active to not trigger also S-DC-Inactive
                if (dc.CreationDate < DateTime.Now.AddDays(-45) && dc.PwdLastSet < DateTime.Now.AddDays(-45)
                    && (dc.LastComputerLogonDate >= DateTime.Now.AddDays(-45)))
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
                        AddRawDetail(dc.DCName, dc.PwdLastSet == DateTime.MinValue ? "Never" : dc.PwdLastSet.ToString("u"));
                    }
                }
            }
            return null;
        }
    }
}
