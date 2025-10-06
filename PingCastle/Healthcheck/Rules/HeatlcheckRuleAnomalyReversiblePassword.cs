//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-ReversiblePwd", RiskRuleCategory.Anomalies, RiskModelCategory.PasswordRetrieval)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 10)]
    [RuleDurANSSI(3, "reversible_password", "Accounts with passwords stored using reversible encryption")]
    [RuleMitreAttackTechnique(MitreAttackTechnique.BruteForcePasswordCracking)]
    public class HeatlcheckRuleAnomalyReversiblePassword : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            foreach (GPPSecurityPolicy policy in healthcheckData.GPPPasswordPolicy)
            {
                foreach (GPPSecurityPolicyProperty property in policy.Properties)
                {
                    if (property.Property == "ClearTextPassword")
                    {
                        if (property.Value > 0)
                        {
                            AddRawDetail(policy.GPOName);
                            break;
                        }
                    }
                }
            }
            return null;
        }
    }
}
