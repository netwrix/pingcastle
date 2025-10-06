//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("P-ControlPathIndirectMany", RiskRuleCategory.PrivilegedAccounts, RiskModelCategory.ControlPath)]
    [RuleComputation(RuleComputationType.TriggerOnThreshold, 25, Threshold: 200, Order: 1)]
    [RuleComputation(RuleComputationType.TriggerOnThreshold, 15, Threshold: 100, Order: 2)]
    [RuleComputation(RuleComputationType.TriggerOnThreshold, 10, Threshold: 50, Order: 3)]
    [RuleComputation(RuleComputationType.TriggerOnThreshold, 5, Threshold: 20, Order: 4)]
    [RuleIntroducedIn(2, 8)]
    [RuleMaturityLevel(2)]
    [RuleNotPartiallyRecomputable]
    [RuleMitreAttackTechnique(MitreAttackTechnique.PermissionGroupsDiscoveryDomainGroups)]
    public class HeatlcheckRulePrivilegedControlPathIndirectMany : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.ControlPaths == null)
                return 0;
            int max = 0;
            foreach (var analysis in healthcheckData.ControlPaths.Data)
            {
                if (analysis.Typology == Data.CompromiseGraphDataTypology.Infrastructure
                    || analysis.Typology == Data.CompromiseGraphDataTypology.PrivilegedAccount)
                {
                    if (analysis.NumberOfIndirectMembers > max)
                    {
                        max = analysis.NumberOfIndirectMembers;
                    }
                    if (analysis.NumberOfIndirectMembers > 20)
                    {
                        AddRawDetail(analysis.Description, analysis.NumberOfIndirectMembers);
                    }
                }
            }
            return max;
        }
    }
}
