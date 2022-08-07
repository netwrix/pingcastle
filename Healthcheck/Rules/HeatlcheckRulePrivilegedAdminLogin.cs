//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

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
            // avoid this check on domains created less than 35 days ago
            if (healthcheckData.DomainCreation.AddDays(35) > healthcheckData.GenerationDate)
            {
                return 100;
            }
            var days = (int)(healthcheckData.GenerationDate - healthcheckData.AdminLastLoginDate).TotalDays;
            // admin login date in the future - can happens when reloading backups
            if (days < 0)
                return 100;
            return days;
        }
    }
}
