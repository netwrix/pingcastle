//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-DCRefuseComputerPwdChange", RiskRuleCategory.Anomalies, RiskModelCategory.PassTheCredential)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 5)]
    [RuleIntroducedIn(2, 7)]
    [RuleSTIG("V-4408", "The domain controller must be configured to allow reset of machine account passwords.", STIGFramework.ActiveDirectoryService2008)]
    [RuleMaturityLevel(2)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.ActiveDirectoryConfiguration)]
    public class HeatlcheckRuleAnomalyDCRefuseComputerPwdChange : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.GPOLsaPolicy != null)
            {
                foreach (GPPSecurityPolicy policy in healthcheckData.GPOLsaPolicy)
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
                    foreach (GPPSecurityPolicyProperty property in policy.Properties)
                    {
                        if (property.Property == "RefusePasswordChange")
                        {
                            if (property.Value == 1)
                            {
                                AddRawDetail(policy.GPOName);
                                break;
                            }
                        }
                    }
                }
            }
            return null;
        }
    }
}
