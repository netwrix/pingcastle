//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-AuditPowershell", RiskRuleCategory.Anomalies, RiskModelCategory.Audit)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 0)]
    [RuleIntroducedIn(2, 8)]
    [RuleSTIG("V-68819", "PowerShell script block logging must be enabled", STIGFramework.Windows10)]
    [RuleMaturityLevel(3)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.Audit)]
    public class HeatlcheckRuleAnomalyAuditPowershell : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            var EnableModuleLogging = false;
            var EnableScriptBlockLogging = false;
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
                        if (property.Property == "EnableModuleLogging" && property.Value > 0)
                        {
                            EnableModuleLogging = true;
                        }
                        if (property.Property == "EnableScriptBlockLogging" && property.Value > 0)
                        {
                            EnableScriptBlockLogging = true;
                        }
                    }
                }
            }
            if (EnableModuleLogging && EnableScriptBlockLogging)
                return 0;
            return 1;
        }
    }
}
