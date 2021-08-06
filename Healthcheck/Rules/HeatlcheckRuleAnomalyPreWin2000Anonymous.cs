//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-PreWin2000Anonymous", RiskRuleCategory.Anomalies, RiskModelCategory.Reconnaissance)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 5)]
    [RuleSTIG("V-8547", "The Anonymous Logon and Everyone groups must not be members of the Pre-Windows 2000 Compatible Access group.")]
    //[RuleBSI("M 2.412")]
    [RuleDurANSSI(2, "compatible_2000_anonymous", "The \"Pre - Windows 2000 Compatible Access\" group includes \"Anonymous\"")]
    [RuleMitreAttackTechnique(MitreAttackTechnique.BruteForcePasswordSpraying)]
    public class HeatlcheckRuleAnomalyPreWin2000Anonymous : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.PreWindows2000AnonymousAccess)
            {
                return 1;
            }
            return 0;
        }
    }
}
