//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-PwdGPO", RiskRuleCategory.Anomalies, RiskModelCategory.PasswordRetrieval)]
    [RuleComputation(RuleComputationType.PerDiscover, 20)]
    [RuleCERTFR("CERTFR-2015-ACT-046", "SECTION00020000000000000000")]
    [RuleMaturityLevel(1)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.UnsecuredCredentialsGroupPolicyPreferences)]
    public class HeatlcheckRuleAnomalyPasswordInGPO : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            foreach (var pass in healthcheckData.GPPPassword)
            {
                AddRawDetail(pass.GPOName, pass.UserName, pass.Password);
            }
            return null;
        }
    }
}
