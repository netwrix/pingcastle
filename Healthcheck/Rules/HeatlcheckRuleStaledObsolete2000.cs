//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("S-OS-2000", RiskRuleCategory.StaleObjects, RiskModelCategory.ObsoleteOS)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 40)]
    [RuleCERTFR("CERTFR-2005-INF-003", "SECTION00032400000000000000")]
    [RuleMaturityLevel(2)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.UpdateSoftware)]
    public class HeatlcheckRuleStaledObsolete2000 : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            foreach (HealthcheckOSData os in healthcheckData.OperatingSystem)
            {
                if (os.OperatingSystem == "Windows 2000")
                {
                    return os.NumberOfOccurence;
                }
            }
            return 0;
        }
    }
}
