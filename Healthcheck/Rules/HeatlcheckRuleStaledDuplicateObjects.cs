//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("S-Duplicate", RiskRuleCategory.StaleObjects, RiskModelCategory.Replication)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 5)]
    [RuleMaturityLevel(4)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.ActiveDirectoryConfiguration)]
    public class HeatlcheckRuleStaledDuplicateObjects : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            return healthcheckData.ComputerAccountData.NumberDuplicate + healthcheckData.UserAccountData.NumberDuplicate;
        }
    }
}
