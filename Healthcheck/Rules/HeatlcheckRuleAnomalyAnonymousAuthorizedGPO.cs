//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-AnonymousAuthorizedGPO", RiskRuleCategory.Anomalies, RiskModelCategory.Reconnaissance)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 5)]
    [RuleSTIG("V-14798", "Directory data (outside the root DSE) of a non-public directory must be configured to prevent anonymous access.", STIGFramework.ActiveDirectoryService2003)]
    [RuleMaturityLevel(2)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.BruteForcePasswordSpraying)]
    public class HeatlcheckRuleAnomalyAnonymousAuthorizedGPO : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            foreach (GPPSecurityPolicy policy in healthcheckData.GPPPasswordPolicy)
            {
                foreach (GPPSecurityPolicyProperty property in policy.Properties)
                {
                    if (property.Property == "RestrictAnonymous" || property.Property == "RestrictAnonymousSAM")
                    {
                        if (property.Value == 0)
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
