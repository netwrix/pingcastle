//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-Guest", RiskRuleCategory.Anomalies, RiskModelCategory.WeakPassword)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 15)]
    [RuleMaturityLevel(1)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.ValidAccountsLocalAccounts)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.ActiveDirectoryConfiguration)]
    [RuleIntroducedIn(2,10,1)]
    public class HeatlcheckRuleAnomalyGuest : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            return healthcheckData.GuestEnabled ? 1 : 0;
        }
    }
}
