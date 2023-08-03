//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("P-UnprotectedOU", RiskRuleCategory.PrivilegedAccounts, RiskModelCategory.IrreversibleChange)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 0)]
    [RuleMaturityLevel(4)]
    [RuleIntroducedIn(3, 1)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.ActiveDirectoryConfiguration)]
    public class HeatlcheckRulePrivilegedUnprotectedOU : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            int i = 0;
            if (healthcheckData.UnprotectedOU != null)
            {
                foreach (var ou in healthcheckData.UnprotectedOU)
                {
                    AddRawDetail(ou);
                    if (i++ >= 10)
                        break;
                }
            }
            return null;
        }
    }
}
