//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.ADWS;
using PingCastle.Rules;
using System;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("P-DelegationKrbtgt", RiskRuleCategory.PrivilegedAccounts, RiskModelCategory.DelegationCheck)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 25)]
    [RuleIntroducedIn(4, 0, 1)]
    [RuleMaturityLevel(1)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.StealorForgeKerberosTickets)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.PrivilegedAccountManagement)]
    public class HeatlcheckRulePrivilegedDelegationKrbtgt : RuleBase<HealthcheckData>
    {
        public static HealthcheckDelegationKrbtgtData ResolveFinding(ADItem x)
        {
            if (x.msDSAllowedToDelegateTo == null || x.msDSAllowedToDelegateTo.Length == 0)
            {
                return null;
            }

            foreach (var delegationTarget in x.msDSAllowedToDelegateTo)
            {
                if (string.IsNullOrEmpty(delegationTarget))
                {
                    continue;
                }

                var servicePart = delegationTarget.Split(new[] { '/' }, StringSplitOptions.None);
                if (servicePart.Length > 0 && string.Equals(servicePart[0], "krbtgt", StringComparison.OrdinalIgnoreCase))
                {
                    return new HealthcheckDelegationKrbtgtData
                    {
                        DistinguishedName = x.DistinguishedName,
                        SAMAccountName = x.SAMAccountName,
                        DelegationTarget = delegationTarget,
                        WhenCreated = x.WhenCreated,
                    };
                }
            }

            return null;
        }

        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.DelegationsToKrbtgt == null)
            {
                return null;
            }

            foreach (var finding in healthcheckData.DelegationsToKrbtgt)
            {
                AddRawDetail(finding.DistinguishedName, finding.SAMAccountName, finding.DelegationTarget, finding.WhenCreated);
            }

            return healthcheckData.DelegationsToKrbtgt.Count;
        }
    }
}
