// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
using System.Collections.Generic;
using System.Linq;
using PingCastle.Rules;
using PingCastleCommon.Utility;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-SpnUnicodeCollision", RiskRuleCategory.Anomalies, RiskModelCategory.PassTheCredential)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 20)]
    [RuleIntroducedIn(4, 0, 1)]
    [RuleMaturityLevel(1)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.ManintheMiddle)]
    public class HeatlcheckRuleAnomalySpnUnicodeCollision : RuleBase<HealthcheckData>
    {
        // Resolves the transient (never serialized) SPN-by-cleaned-value map built during collection
        // (see HealthcheckAnalyzer.RecordSpnsForUnicodeCollisionCheck) into the findings list
        // that gets persisted on HealthcheckData.SPNUnicodeCollisions.
        public static List<HealthcheckSPNUnicodeFinding> ResolveFindings(Dictionary<string, List<(string AccountName, string RawSpn)>> spnCleanedValueToAccounts)
        {
            var findings = new List<HealthcheckSPNUnicodeFinding>();

            foreach (var rawGroup in spnCleanedValueToAccounts.Values)
            {
                var group = rawGroup.Distinct().ToList();
                var distinctRawValues = group.Select(g => g.RawSpn).Distinct().ToList();
                if (distinctRawValues.Count > 1)
                {
                    foreach (var entry in group)
                    {
                        if (!SpnUnicodeHelper.HasInvisibleChar(entry.RawSpn))
                        {
                            continue;
                        }

                        var targetAccounts = group
                            .Where(g => g.AccountName != entry.AccountName)
                            .Select(g => g.AccountName)
                            .Distinct()
                            .ToList();

                        var targetAccountText = targetAccounts.Count > 0 ? string.Join(", ", targetAccounts) : "-";

                        findings.Add(new HealthcheckSPNUnicodeFinding
                        {
                            SPN = SpnUnicodeHelper.ToVisibleString(entry.RawSpn),
                            UnicodeSPNAccount = entry.AccountName,
                            TargetAccount = targetAccountText,
                            IsCollision = true,
                        });
                    }
                }
                else if (distinctRawValues.Count == 1 && SpnUnicodeHelper.HasInvisibleChar(group[0].RawSpn))
                {
                    findings.Add(new HealthcheckSPNUnicodeFinding
                    {
                        SPN = SpnUnicodeHelper.ToVisibleString(group[0].RawSpn),
                        UnicodeSPNAccount = group[0].AccountName,
                        TargetAccount = "-",
                        IsCollision = false,
                    });
                }
            }

            return findings;
        }

        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.SPNUnicodeCollisions == null || healthcheckData.SPNUnicodeCollisions.Count == 0)
            {
                return null;
            }

            foreach (var finding in healthcheckData.SPNUnicodeCollisions)
            {
                AddRawDetail(finding.SPN, finding.UnicodeSPNAccount, finding.TargetAccount,
                    finding.IsCollision ? "Unicode SPN is present and matches target account" : "Unicode SPN is present, no matching target account");
            }

            return healthcheckData.SPNUnicodeCollisions.Count;
        }
    }
}
