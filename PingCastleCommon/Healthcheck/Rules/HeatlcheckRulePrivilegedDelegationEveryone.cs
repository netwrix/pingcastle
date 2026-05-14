using PingCastle.Graph.Reporting;
//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("P-DelegationEveryone", RiskRuleCategory.PrivilegedAccounts, RiskModelCategory.DelegationCheck)]
    [RuleComputation(RuleComputationType.PerDiscover, 15)]
    [RuleANSSI("R18", "subsubsection.3.3.2")]
    [RuleMaturityLevel(2)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.ForcedAuthentication)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.ActiveDirectoryConfiguration)]
    [RuleSTIG("V-205741", "Windows Server 2019 Active Directory Group Policy objects must have proper access control permissions.", STIGFramework.WindowsServer2019)]
    public class HeatlcheckRulePrivilegedDelegationEveryone : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            foreach (HealthcheckDelegationData delegation in healthcheckData.Delegations)
            {
                if (delegation.Account == GraphObjectReference.AuthenticatedUsers || delegation.Account == GraphObjectReference.Everyone
                        || delegation.Account == GraphObjectReference.DomainUsers || delegation.Account == GraphObjectReference.DomainComputers
                        || delegation.SecurityIdentifier == "S-1-5-32-545" || delegation.SecurityIdentifier.EndsWith("-513") || delegation.SecurityIdentifier.EndsWith("-515")
                        || delegation.Account == GraphObjectReference.Anonymous)
                {
                    AddRawDetail(delegation.DistinguishedName, delegation.Account, delegation.Right);
                }
            }
            return null;
        }
    }
}
