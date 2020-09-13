//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//

using PingCastle.Rules;

namespace PingCastle.HealthCheck.Rules
{
    [RuleModel("A-PreWin2000Anonymous", RiskRuleCategory.Anomalies, RiskModelCategory.Reconnaissance)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 5)]
    [RuleSTIG("V-8547", "The Anonymous Logon and Everyone groups must not be members of the Pre-Windows 2000 Compatible Access group.")]

    //[RuleBSI("M 2.412")]
    [RuleDurANSSI(2, "compatible_2000_anonymous", "The \"Pre - Windows 2000 Compatible Access\" group includes \"Anonymous\"")]
    public class HealthCheckRuleAnomalyPreWin2000Anonymous : RuleBase<HealthCheckData>
    {
        protected override int? AnalyzeDataNew(HealthCheckData healthcheckData)
        {
            if (healthcheckData.PreWindows2000AnonymousAccess)
            {
                return 1;
            }
            return 0;
        }
    }
}