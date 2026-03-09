//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;
using System.Collections.Generic;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("P-UnconstrainedDelegation", RiskRuleCategory.PrivilegedAccounts, RiskModelCategory.DelegationCheck)]
    [RuleComputation(RuleComputationType.PerDiscover, 5)]
    [RuleANSSI("R18", "subsubsection.3.3.2")]
    [RuleIntroducedIn(2, 6)]
    [RuleDurANSSI(2, "delegation_t4d", "Unconstrained authentication delegation")]
    [RuleMitreAttackTechnique(MitreAttackTechnique.ForcedAuthentication)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.ActiveDirectoryConfiguration)]
    public class HeatlcheckRulePrivilegedUnconstrainedDelegation : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            var dcDistinguishedNames = new HashSet<string>();
            if (healthcheckData.DomainControllers != null)
            {
                foreach (var dc in healthcheckData.DomainControllers)
                {
                    dcDistinguishedNames.Add(dc.DistinguishedName);
                }
            }

            void AddDelegations(IEnumerable<dynamic> delegations, bool skipDomainControllers)
            {
                if (delegations == null)
                {
                    return;
                }

                foreach (var delegation in delegations)
                {
                    if (skipDomainControllers && dcDistinguishedNames.Contains(delegation.DistinguishedName))
                        continue;
                    AddRawDetail(delegation.DistinguishedName, delegation.Name);
                }
            }

            AddDelegations(healthcheckData.UserAccountData.ListEnabledTrustedToAuthenticateForDelegation, false);
            AddDelegations(healthcheckData.ComputerAccountData.ListEnabledTrustedToAuthenticateForDelegation, true);
            AddDelegations(healthcheckData.UserAccountData.ListDisabledTrustedToAuthenticateForDelegation, false);
            AddDelegations(healthcheckData.ComputerAccountData.ListDisabledTrustedToAuthenticateForDelegation, true);

            return null;
        }
    }
}
