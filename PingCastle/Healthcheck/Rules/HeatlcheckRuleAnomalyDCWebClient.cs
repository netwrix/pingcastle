//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-DC-WebClient", RiskRuleCategory.Anomalies, RiskModelCategory.PassTheCredential)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 0)]
    [RuleIntroducedIn(2, 11)]
    [RuleMaturityLevel(4)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.ForcedAuthentication)]
    public class HeatlcheckRuleAnomalyDCWebClient : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            foreach (var DC in healthcheckData.DomainControllers)
            {
                if (DC.WebClientEnabled)
                {
                    AddRawDetail(DC.DCName);
                }
            }
            return null;
        }
    }
}
