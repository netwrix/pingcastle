//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-SmartCardRequired", RiskRuleCategory.Anomalies, RiskModelCategory.PassTheCredential)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 30)]
    [RuleSTIG("V-72821", "All accounts, privileged and unprivileged, that require smart cards must have the underlying NT hash rotated at least every 60 days.")]
    [RuleANSSI("R38", "paragraph.3.6.2.2")]
    [RuleMaturityLevel(3)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.BruteForcePasswordCracking)]
    public class HeatlcheckRuleAnomalySmartCardRequired : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            return healthcheckData.SmartCardNotOK.Count;
        }
    }
}
