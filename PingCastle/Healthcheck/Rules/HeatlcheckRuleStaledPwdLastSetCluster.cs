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
    [RuleModel("S-PwdLastSet-Cluster", RiskRuleCategory.StaleObjects, RiskModelCategory.InactiveUserOrComputer)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 5)]
    [RuleDurANSSI(2, "password_change_cluster_no_change_3years", "Windows server cluster accounts with passwords unchanged for more than 3 years")]
    [RuleSTIG("V-63653", "The computer account password must not be prevented from being reset.", STIGFramework.Windows10)]
    [RuleSTIG("V-3373", "The maximum age for machine account passwords is not set to requirements.", STIGFramework.Windows7)]
    [RuleIntroducedIn(3, 3)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.ActiveDirectoryConfiguration)]
    public class HeatlcheckRuleStaledPwdLastSetCluster : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.ListClusterPwdNotChanged != null)
            {
                foreach (var c in healthcheckData.ListClusterPwdNotChanged)
                {
                    // workaround for timeproblem with DC that sets lastlongdate in the future
                    var date = c.LastLogonDate;
                    if (date > DateTime.Now)
                        date = DateTime.Now;

                    AddRawDetail(c.Name, c.CreationDate, c.LastLogonDate, c.PwdLastSet);
                }
            }
            return null;
        }
    }
}
