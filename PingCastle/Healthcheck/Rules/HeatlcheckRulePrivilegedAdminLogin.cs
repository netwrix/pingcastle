//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;
using System;
using System.Diagnostics;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("P-AdminLogin", RiskRuleCategory.PrivilegedAccounts, RiskModelCategory.AdminControl)]
    [RuleComputation(RuleComputationType.TriggerIfLessThan, 20, Threshold: 35)]
    [RuleMaturityLevel(3)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.PrivilegedAccountManagement)]
    public class HeatlcheckRulePrivilegedAdminLogin : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            // computer threshold if computation rules have been changed
            var threshold = int.MaxValue;
            foreach (var rule in this.RuleComputation)
            {
                if (rule.Threshold > 0)
                {
                    if (rule.Threshold < threshold)
                        threshold = rule.Threshold;
                }
            }
            // defensive programming in case of incorrect customization
            if (threshold == int.MaxValue)
            {
                threshold = 35;
            }
            Trace.WriteLine("P-AdminLogin: threshold is " + threshold);

            // avoid this check on domains created less than 35 days ago
            if (healthcheckData.DomainCreation.AddDays(threshold) > healthcheckData.GenerationDate)
            {
                Trace.WriteLine("P-AdminLogin: domain is too young - ignore");
                return 3 * threshold;
            }

            int days;
            int minDays = int.MaxValue;
            if (healthcheckData.DomainControllers != null)
            {
                Trace.WriteLine("P-AdminLogin: using new computation model");
                foreach (var dc in healthcheckData.DomainControllers)
                {
                    if (dc.AdminLocalLogin == DateTime.MinValue)
                    {
                        Trace.WriteLine("P-AdminLogin: DC " + dc.DCName + " ignored");
                        continue;
                    }

                    days = (int)(healthcheckData.GenerationDate - dc.AdminLocalLogin).TotalDays;
                    // admin login date in the future - can happens when reloading backups
                    if (days < 0)
                        continue;
                    if (days <= threshold)
                    {
                        AddRawDetail(dc.DCName, dc.AdminLocalLogin.ToString("u"));
                        if (minDays > days)
                            minDays = days;
                    }
                }
                if (minDays != int.MaxValue)
                {
                    Trace.WriteLine("P-AdminLogin: computation value: " + minDays);
                    return minDays;
                }
                return 3 * threshold;
            }

            Trace.WriteLine("P-AdminLogin: fallback to default computation model");
            days = (int)(healthcheckData.GenerationDate - healthcheckData.AdminLastLoginDate).TotalDays;
            // admin login date in the future - can happens when reloading backups
            if (days < 0)
                return 3 * threshold;
            return days;
        }
    }
}
