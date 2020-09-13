//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//

using PingCastle.Rules;

namespace PingCastle.HealthCheck.Rules
{
    [RuleModel("S-DCRegistration", RiskRuleCategory.StaleObjects, RiskModelCategory.Provisioning)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 10)]
    [RuleIntroducedIn(2, 9)]
    [RuleDurANSSI(1, "dc_inconsistent_uac", "Domain controllers in inconsistent state")]
    public class HealthCheckRuleStaleDCRegistrationEnabled : RuleBase<HealthCheckData>
    {
        protected override int? AnalyzeDataNew(HealthCheckData healthcheckData)
        {
            foreach (var dc in healthcheckData.DomainControllers)
            {
                if (!string.IsNullOrEmpty(dc.RegistrationProblem))
                {
                    AddRawDetail(dc.DCName, dc.RegistrationProblem);
                }
            }
            return null;
        }
    }
}