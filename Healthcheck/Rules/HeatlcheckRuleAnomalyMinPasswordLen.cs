//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-MinPwdLen", RiskRuleCategory.Anomalies, RiskModelCategory.WeakPassword)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 10)]
    //[RuleBSI("M 4.314")]
    [RuleDurANSSI(2, "privileged_members_password", "Privileged group members with weak password policy")]
    [RuleMaturityLevel(2)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.PasswordPolicyDiscovery)]
    public class HeatlcheckRuleAnomalyMinPasswordLen : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            foreach (GPPSecurityPolicy policy in healthcheckData.GPPPasswordPolicy)
            {
                // skip the GPO belongins check when GPOId is not set (PSO)
                if (!string.IsNullOrEmpty(policy.GPOId))
                {
                    if (healthcheckData.GPOInfoDic == null || !healthcheckData.GPOInfoDic.ContainsKey(policy.GPOId))
                    {
                        continue;
                    }
                    var refGPO = healthcheckData.GPOInfoDic[policy.GPOId];
                    if (refGPO.IsDisabled)
                    {
                        continue;
                    }
                    if (refGPO.AppliedTo == null || refGPO.AppliedTo.Count == 0)
                    {
                        continue;
                    }
                }
                foreach (GPPSecurityPolicyProperty property in policy.Properties)
                {
                    if (property.Property == "MinimumPasswordLength")
                    {
                        if (property.Value < 8)
                        {
                            AddRawDetail(policy.GPOName);
                        }
                    }
                }
            }
            return null;
        }
    }
}
