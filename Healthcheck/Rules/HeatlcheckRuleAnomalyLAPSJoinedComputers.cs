//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-LAPS-Joined-Computers", RiskRuleCategory.Anomalies, RiskModelCategory.PassTheCredential)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 5)]
    [RuleMaturityLevel(3)]
    [RuleIntroducedIn(2,9,3)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.CredentialsfromPasswordStoresPasswordManagers)]
    public class HeatlcheckRuleAnomalyLAPSJoinedComputers : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.ListLAPSJoinedComputersToReview != null)
            {
                return healthcheckData.ListLAPSJoinedComputersToReview.Count;
            }
            return 0;
        }
    }
}
