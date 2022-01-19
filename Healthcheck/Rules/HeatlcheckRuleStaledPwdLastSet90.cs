//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("S-PwdLastSet-90", RiskRuleCategory.StaleObjects, RiskModelCategory.InactiveUserOrComputer)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 15)]
    [RuleDurANSSI(2, "password_change_server_no_change_90", "Servers with passwords unchanged for more than 90 days")]
    [RuleSTIG("V-63653", "The computer account password must not be prevented from being reset.", STIGFramework.Windows10)]
    [RuleSTIG("V-3373", "The maximum age for machine account passwords is not set to requirements.", STIGFramework.Windows7)]
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
                    if (c.PwdLastSet.AddDays(90) <= c.LastLogonDate)
                    {
                        AddRawDetail(c.Name, c.CreationDate, c.LastLogonDate, c.PwdLastSet);
                    }
                }
            }
            return null;
        }
    }
}
