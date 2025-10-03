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
    [RuleModel("S-DC-NotUpdated", RiskRuleCategory.StaleObjects, RiskModelCategory.VulnerabilityManagement)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 15)]
    //[RuleBSI("M 4.315")]
    [RuleMaturityLevel(1)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.UpdateSoftware)]
    public class HeatlcheckRuleStaledDCNotRebooted : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.DomainControllers != null && healthcheckData.DomainControllers.Count > 0)
            {
                foreach (var DC in healthcheckData.DomainControllers)
                {
                    if (DC.AzureADKerberos)
                    {
                        continue;
                    }
                    if (DC.StartupTime != DateTime.MinValue)
                    {
                        if (DC.StartupTime.AddMonths(6) < DateTime.Now)
                        {
                            AddRawDetail(DC.DCName, "StartupTime=" + DC.StartupTime);
                        }
                    }
                    else
                    {
                        if (DC.LastComputerLogonDate != DateTime.MinValue && DC.LastComputerLogonDate.AddMonths(6) < DateTime.Now)
                        {
                            AddRawDetail(DC.DCName, "LastComputerLogonDate=" + DC.LastComputerLogonDate);
                        }
                    }
                }
            }
            return null;
        }
    }
}
