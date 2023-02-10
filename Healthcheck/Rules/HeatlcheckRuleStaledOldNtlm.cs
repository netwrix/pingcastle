//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("S-OldNtlm", RiskRuleCategory.StaleObjects, RiskModelCategory.OldAuthenticationProtocols)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 15)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.ManintheMiddleLLMNRNBTNSPoisoningandSMBRelay)]
    [RuleANSSI("R37", "paragraph.3.6.2.1")]
    [RuleMaturityLevel(2)]
    [RuleIntroducedIn(2,11,2)]
    public class HeatlcheckRuleStaledOldNtlm : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            bool found = false;
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
                    // The default level value for LmCompatibilityLevel for each version of Windows is as follows:
                    // Windows XP: 0 Windows 2003: 2 Vista/2008 3 Win7/2008 R2 3
                    // DC is not 5
                    foreach (GPPSecurityPolicyProperty property in policy.Properties)
                    {
                        if (property.Property == "LmCompatibilityLevel")
                        {
                            found = true;
                            if (property.Value < 5)
                            {
                                AddRawDetail(policy.GPOName, property.Value);
                            }
                        }
                    }
                }
            }
            if (!found)
            {
                AddRawDetail("Windows default without an active GPO", "3");
            }
            return null;
        }
    }
}
