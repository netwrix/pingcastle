//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//

using PingCastle.Rules;

namespace PingCastle.HealthCheck.Rules
{
	[RuleModel("S-OS-NT", RiskRuleCategory.StaleObjects, RiskModelCategory.ObsoleteOS)]
	[RuleComputation(RuleComputationType.TriggerOnPresence, 60)]
	[RuleCERTFR("CERTFR-2005-INF-003", "SECTION00032400000000000000")]
    [RuleMaturityLevel(2)]
    public class HealthCheckRuleStaledObsoleteNT4 : RuleBase<HealthCheckData>
    {
		protected override int? AnalyzeDataNew(HealthCheckData healthcheckData)
        {
            foreach (HealthCheckOSData os in healthcheckData.OperatingSystem)
            {
                if (os.OperatingSystem == "Windows NT")
                {
                    return os.NumberOfOccurence;
                }
            }
            return 0;
        }
    }
}
