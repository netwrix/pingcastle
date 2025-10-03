//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Graph.Database;
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("P-DelegationDCsourcedeleg", RiskRuleCategory.PrivilegedAccounts, RiskModelCategory.DelegationCheck)]
    [RuleComputation(RuleComputationType.PerDiscover, 25)]
    [RuleDurANSSI(1, "delegation_sourcedeleg", "Resource-based constrained delegation on domain controlers")]
    [RuleIntroducedIn(2, 9)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.ForcedAuthentication)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.ActiveDirectoryConfiguration)]
    public class HeatlcheckRulePrivilegedDelegationDCsourcedeleg : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            foreach (var dc in healthcheckData.DomainControllers)
            {
                if (dc.Delegations != null)
                {
                    foreach (var delegation in dc.Delegations)
                    {
                        if (delegation.DelegationType == RelationType.msDS_Allowed_To_Act_On_Behalf_Of_Other_Identity.ToString())
                        {
                            AddRawDetail(dc.DCName, delegation.Delegate, delegation.DelegateSid);
                        }
                    }
                }
            }
            return null;
        }
    }
}
