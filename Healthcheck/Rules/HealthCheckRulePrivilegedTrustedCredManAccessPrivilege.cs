//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//

using System;
using PingCastle.Rules;

namespace PingCastle.HealthCheck.Rules
{
    [RuleModel("P-TrustedCredManAccessPrivilege", RiskRuleCategory.PrivilegedAccounts, RiskModelCategory.PrivilegeControl)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 5)]
    [RuleSTIG("V-63843", "The Access Credential Manager as a trusted caller user right must not be assigned to any groups or accounts", STIGFramework.Windows10)]
    [RuleIntroducedIn(2, 8)]
    [RuleMaturityLevel(3)]
    public class HealthCheckRulePrivilegedTrustedCredManAccessPrivilege : RuleBase<HealthCheckData>
    {
        protected override int? AnalyzeDataNew(HealthCheckData healthcheckData)
        {
            foreach (var privilege in healthcheckData.GPPRightAssignment)
            {
                if (string.Equals(privilege.Privilege, "SeTrustedCredManAccessPrivilege", StringComparison.OrdinalIgnoreCase))
                {
                    AddRawDetail(privilege.GPOName, privilege.User);
                }
            }
            return null;
        }
    }
}