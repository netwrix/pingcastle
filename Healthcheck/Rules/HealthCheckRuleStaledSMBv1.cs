//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//

using PingCastle.Rules;

namespace PingCastle.HealthCheck.Rules
{
    [RuleModel("S-SMB-v1", RiskRuleCategory.StaleObjects, RiskModelCategory.OldAuthenticationProtocols)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 10)]

    //[RuleBSI("M 2.412")]
    [RuleCERTFR("CERTFR-2017-ACT-019", "SECTION00010000000000000000")]
    [RuleCERTFR("CERTFR-2016-ACT-039", "SECTION00010000000000000000")]
    [RuleMaturityLevel(3)]
    public class HealthCheckRuleStaledSMBv1 : RuleBase<HealthCheckData>
    {
        protected override int? AnalyzeDataNew(HealthCheckData healthcheckData)
        {
            // smb v1 enabled ?
            if (healthcheckData.DomainControllers != null && healthcheckData.DomainControllers.Count > 0)
            {
                foreach (var DC in healthcheckData.DomainControllers)
                {
                    if (DC.SupportSMB1)
                    {
                        AddRawDetail(DC.DCName);
                    }
                }
            }
            return null;
        }
    }
}