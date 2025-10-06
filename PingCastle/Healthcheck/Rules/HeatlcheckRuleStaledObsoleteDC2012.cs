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
    [RuleModel("S-DC-2012", RiskRuleCategory.StaleObjects, RiskModelCategory.ObsoleteOS)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 5)]
    [RuleSTIG("V-8551", "The domain functional level must be at a Windows Server version still supported by Microsoft.")]
    [RuleANSSI("R12", "subsection.3.1")]
    [RuleDurANSSI(1, "warning_dc_obsolete", "DC/RODC with an obsolete operating system")]
    [RuleIntroducedIn(3, 1)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.UpdateSoftware)]
    public class HeatlcheckRuleStaledObsoleteDC2012 : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (DateTime.Now < new DateTime(2023, 10, 10))
                return null;
            if (HeatlcheckRuleStaledObsolete2012.IPaidSupportWin2012)
                return 0;
            int w2012 = 0;
            foreach (var dc in healthcheckData.DomainControllers)
            {
                if (dc.OperatingSystem == "Windows 2012")
                {
                    w2012++;
                }
            }
            return w2012;
        }
    }
}
