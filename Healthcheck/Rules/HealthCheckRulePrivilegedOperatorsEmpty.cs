//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//

using PingCastle.Rules;

namespace PingCastle.HealthCheck.Rules
{
    [RuleModel("P-OperatorsEmpty", RiskRuleCategory.PrivilegedAccounts, RiskModelCategory.AdminControl)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 0)]
    [RuleANSSI("R27", "subsection.3.5")]
    [RuleMaturityLevel(3)]
    public class HealthCheckRulePrivilegedOperatorsEmpty : RuleBase<HealthCheckData>
    {
        protected override int? AnalyzeDataNew(HealthCheckData healthcheckData)
        {
            foreach (var group in healthcheckData.PrivilegedGroups)
            {
                if (group.GroupName == "Account Operators" || group.GroupName == "Server Operators")
                {
                    if (group.NumberOfMember > 0)
                    {
                        AddRawDetail(group.GroupName, group.NumberOfMember);
                    }
                }
            }
            return null;
        }
    }
}