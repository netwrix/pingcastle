using PingCastle.Graph.Reporting;
//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;
using System;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-MembershipEveryone", RiskRuleCategory.Anomalies, RiskModelCategory.LocalGroupVulnerability)]
    [RuleComputation(RuleComputationType.PerDiscover, 15)]
    [RuleMaturityLevel(1)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.ActiveDirectoryConfiguration)]
    public class HeatlcheckRuleAnomalyMembershipEveryone : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            foreach (GPOMembership membership in healthcheckData.GPOLocalMembership)
            {
                if (membership.User == GraphObjectReference.AuthenticatedUsers || membership.User == GraphObjectReference.Everyone || 
                        membership.User == GraphObjectReference.Users || membership.User == GraphObjectReference.Anonymous|| 
                        membership.User == GraphObjectReference.DomainUsers || membership.User == GraphObjectReference.DomainComputers)
                {
                    if (string.Equals(membership.MemberOf, "BUILTIN\\Users", StringComparison.OrdinalIgnoreCase))
                        continue;
                    AddRawDetail(membership.GPOName, membership.MemberOf, membership.User);
                }
            }
            return null;
        }
    }
}
