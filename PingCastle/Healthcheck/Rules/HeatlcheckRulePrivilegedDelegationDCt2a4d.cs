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
    [RuleModel("P-DelegationDCt2a4d", RiskRuleCategory.PrivilegedAccounts, RiskModelCategory.DelegationCheck)]
    [RuleComputation(RuleComputationType.PerDiscover, 25)]
    [RuleDurANSSI(1, "delegation_t2a4d", "Constrained delegation with protocol transition to a domain controller service")]
    [RuleIntroducedIn(2, 9)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.ForcedAuthentication)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.ActiveDirectoryConfiguration)]
    public class HeatlcheckRulePrivilegedDelegationDCt2a4d : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            foreach (var dc in healthcheckData.DomainControllers)
            {
                if (dc.Delegations != null)
                {
                    foreach (var delegation in dc.Delegations)
                    {
                        if (delegation.DelegationType == RelationType.msDS_Allowed_To_Delegate_To_With_Protocol_Transition.ToString())
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
