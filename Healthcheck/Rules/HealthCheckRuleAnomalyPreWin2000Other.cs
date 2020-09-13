//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//

using PingCastle.Rules;

namespace PingCastle.HealthCheck.Rules
{
	[RuleModel("A-PreWin2000Other", RiskRuleCategory.Anomalies, RiskModelCategory.Reconnaissance)]
	[RuleComputation(RuleComputationType.TriggerOnPresence, 2)]
    [RuleIntroducedIn(2,9)]
    [RuleDurANSSI(3, "compatible_2000_not_default", "Use of the \"Pre-Windows 2000 Compatible Access\" group")]
    public class HealthCheckRuleAnomalyPreWin2000Other : RuleBase<HealthCheckData>
    {
		protected override int? AnalyzeDataNew(HealthCheckData healthcheckData)
        {
            if (healthcheckData.PreWindows2000NoDefault)
            {
                return 1;
            }
            return 0;
        }
    }
}
