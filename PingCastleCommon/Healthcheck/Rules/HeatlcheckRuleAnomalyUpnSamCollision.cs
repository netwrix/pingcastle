// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
using System;
using System.Collections.Generic;
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-UpnSamCollision", RiskRuleCategory.Anomalies, RiskModelCategory.PassTheCredential)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 30)]
    [RuleIntroducedIn(4, 0, 1)]
    [RuleMaturityLevel(1)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.StealorForgeKerberosTickets)]
    public class HeatlcheckRuleAnomalyUpnSamCollision : RuleBase<HealthcheckData>
    {
        // Resolves the transient (never serialized) candidate list built during collection
        // (see HealthcheckAnalyzer.RecordAccountForUpnSamCollisionCheck, which already excludes
        // self-matches) into the findings list that gets persisted on HealthcheckData.UpnSamCollisions.
        public static List<HealthcheckUpnSamCollisionData> ResolveFindings(HashSet<string> allSamAccountNames, List<(string SAMAccountName, string DistinguishedName, string UserPrincipalName, string UpnLocalPart, DateTime WhenCreated)> candidates)
        {
            var findings = new List<HealthcheckUpnSamCollisionData>();

            foreach (var candidate in candidates)
            {
                if (!allSamAccountNames.Contains(candidate.UpnLocalPart))
                {
                    continue;
                }

                findings.Add(new HealthcheckUpnSamCollisionData
                {
                    DistinguishedName = candidate.DistinguishedName,
                    SAMAccountName = candidate.SAMAccountName,
                    UserPrincipalName = candidate.UserPrincipalName,
                    MatchingAccountSamAccountName = candidate.UpnLocalPart,
                    WhenCreated = candidate.WhenCreated,
                });
            }

            return findings;
        }

        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.UpnSamCollisions == null || healthcheckData.UpnSamCollisions.Count == 0)
            {
                return null;
            }

            foreach (var finding in healthcheckData.UpnSamCollisions)
            {
                AddRawDetail(finding.DistinguishedName, finding.SAMAccountName, finding.UserPrincipalName, finding.MatchingAccountSamAccountName, finding.WhenCreated);
            }

            return healthcheckData.UpnSamCollisions.Count;
        }
    }
}
