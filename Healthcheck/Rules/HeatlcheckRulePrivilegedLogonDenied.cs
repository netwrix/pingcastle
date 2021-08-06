using PingCastle.Graph.Reporting;
//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;
using System.Collections.Generic;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("P-LogonDenied", RiskRuleCategory.PrivilegedAccounts, RiskModelCategory.AccountTakeOver)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 1)]
    [RuleIntroducedIn(2, 8)]
    [RuleMaturityLevel(4)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.PrivilegedAccountManagement)]
    public class HeatlcheckRulePrivilegedLogonDenied : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.UserAccountData.NumberActive > 200 && healthcheckData.ComputerAccountData.NumberActive > 200)
            {
                var dangerousGroups = new List<string>() {
                    GraphObjectReference.DomainAdministrators,
                    GraphObjectReference.Administrators,
                };
                bool restrictionFound = false;
                foreach (var policy in healthcheckData.GPPLoginAllowedOrDeny)
                {
                    if (policy.Privilege == "SeDenyRemoteInteractiveLogonRight" || policy.Privilege == "SeDenyInteractiveLogonRight")
                    {
                        if (policy.User == GraphObjectReference.Administrators || policy.User == GraphObjectReference.DomainAdministrators)
                        {
                            restrictionFound = true;
                            break;
                        }
                    }
                }
                if (!restrictionFound)
                    return 1;
            }
            return 0;
        }
    }
}
