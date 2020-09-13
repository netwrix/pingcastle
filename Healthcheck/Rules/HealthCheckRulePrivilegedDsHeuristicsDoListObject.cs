//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//

using PingCastle.Rules;

namespace PingCastle.HealthCheck.Rules
{
    [RuleModel("P-DsHeuristicsDoListObject", RiskRuleCategory.PrivilegedAccounts, RiskModelCategory.ACLCheck)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 0)]
    [RuleIntroducedIn(2, 7)]
    [RuleMaturityLevel(2)]
    public class HealthCheckRulePrivilegedDsHeuristicsDoListObject : RuleBase<HealthCheckData>
    {
        protected override int? AnalyzeDataNew(HealthCheckData healthcheckData)
        {
            if (healthcheckData.DsHeuristicsDoListObject)
            {
                return 1;
            }
            return 0;
        }
    }
}