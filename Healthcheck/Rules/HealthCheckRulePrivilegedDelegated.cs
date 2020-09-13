//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//

using PingCastle.Rules;

namespace PingCastle.HealthCheck.Rules
{
    [RuleModel("P-Delegated", RiskRuleCategory.PrivilegedAccounts, RiskModelCategory.AccountTakeOver)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 20)]
    [RuleSTIG("V-36435", "Delegation of privileged accounts must be prohibited.")]
    [RuleMaturityLevel(3)]
    public class HealthCheckRulePrivilegedDelegated : RuleBase<HealthCheckData>
    {
        protected override int? AnalyzeDataNew(HealthCheckData healthcheckData)
        {
            int adminCanBeDelegated = 0;
            foreach (var member in healthcheckData.AllPrivilegedMembers)
            {
                if (member.CanBeDelegated)
                    adminCanBeDelegated++;
            }
            return adminCanBeDelegated;
        }
    }
}