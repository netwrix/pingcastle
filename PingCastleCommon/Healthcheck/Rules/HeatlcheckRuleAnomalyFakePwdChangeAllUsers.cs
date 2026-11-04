// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
using System;
using System.Collections.Generic;
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-FakePwdChangeAllUsers", RiskRuleCategory.Anomalies, RiskModelCategory.PassTheCredential)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 5)]
    [RuleIntroducedIn(4, 1)]
    [RuleMaturityLevel(4)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.AccountManipulation)]
    public class HeatlcheckRuleAnomalyFakePwdChangeAllUsers : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.UserAccountData?.ListFakePwdChangeAllUsers == null || healthcheckData.UserAccountData.ListFakePwdChangeAllUsers.Count == 0)
            {
                return null;
            }

            // Build a HashSet of privileged member DistinguishedNames
            var privilegedDistinguishedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (healthcheckData.PrivilegedGroups != null)
            {
                foreach (var group in healthcheckData.PrivilegedGroups)
                {
                    if (group.Members != null)
                    {
                        foreach (var member in group.Members)
                        {
                            if (!string.IsNullOrEmpty(member.DistinguishedName))
                            {
                                privilegedDistinguishedNames.Add(member.DistinguishedName);
                            }
                        }
                    }
                }
            }

            // Report findings for non-privileged accounts
            int reportedCount = 0;
            foreach (var detail in healthcheckData.UserAccountData.ListFakePwdChangeAllUsers)
            {
                if (!privilegedDistinguishedNames.Contains(detail.DistinguishedName ?? string.Empty))
                {
                    AddRawDetail(
                        detail.Name,
                        detail.PwdLastSet.ToUniversalTime().ToString("u"),
                        detail.Event.ToUniversalTime().ToString("u"),
                        "pwdLastSet refreshed without a matching unicodePwd change");
                    reportedCount++;
                }
            }

            return reportedCount > 0 ? reportedCount : null;
        }
    }
}
