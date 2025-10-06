//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-PreWin2000AuthenticatedUsers", RiskRuleCategory.Anomalies, RiskModelCategory.Reconnaissance)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 0)]
    //[RuleBSI("M 2.412")]
    [RuleMaturityLevel(5)]
    [RuleIntroducedIn(2,9,3)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.ExploitationofRemoteServices)]
    public class HeatlcheckRuleAnomalyPreWin2000AuthenticatedUsers : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.PreWindows2000AuthenticatedUsers)
            {
                return 1;
            }
            return 0;
        }
    }
}
