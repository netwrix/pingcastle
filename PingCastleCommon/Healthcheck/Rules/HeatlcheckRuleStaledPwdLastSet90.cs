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
    [RuleModel("S-PwdLastSet-90", RiskRuleCategory.StaleObjects, RiskModelCategory.InactiveUserOrComputer)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 15)]
    [RuleDurANSSI(2, "password_change_server_no_change_90", "Servers with passwords unchanged for more than 90 days")]
    [RuleSTIG("V-220918", "The computer account password must not be prevented from being reset.", STIGFramework.Windows10)]
    [RuleSTIG("V-205911", "Windows Server 2019 maximum age for machine account passwords must be configured to 30 days or less.", STIGFramework.WindowsServer2019)]
    [RuleIntroducedIn(2, 9)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.ActiveDirectoryConfiguration)]
    public class HeatlcheckRuleStaledPwdLastSet90 : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.ListComputerPwdNotChanged != null)
            {
                foreach (var c in healthcheckData.ListComputerPwdNotChanged)
                {
                    // workaround for timeproblem with DC that sets lastlongdate in the future
                    var date = c.LastLogonDate;
                    if (date > DateTime.Now)
                        date = DateTime.Now;

                    if (c.PwdLastSet.AddDays(90) <= date)
                    {
                        AddRawDetail(c.Name, c.CreationDate, c.LastLogonDate, c.PwdLastSet);
                    }
                }
            }
            return null;
        }
    }
}
