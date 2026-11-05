// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
using System;
using System.Collections.Generic;
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("P-FakePwdChangeAdmin", RiskRuleCategory.PrivilegedAccounts, RiskModelCategory.PassTheCredential)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 15)]
    [RuleIntroducedIn(4, 1)]
    [RuleMaturityLevel(2)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.AccountManipulation)]
    public class HeatlcheckRulePrivilegedFakePwdChangeAdmin : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.PrivilegedGroups == null || healthcheckData.PrivilegedGroups.Count == 0)
            {
                return null;
            }

            if (healthcheckData.UserAccountData?.ListFakePwdChangeAllUsers == null || healthcheckData.UserAccountData.ListFakePwdChangeAllUsers.Count == 0)
            {
                return null;
            }

            // Build a map from ListFakePwdChangeAllUsers by DN (case-insensitive)
            var fakePasswordChangeMap = new Dictionary<string, HealthcheckAccountDetailData>(StringComparer.OrdinalIgnoreCase);
            foreach (var detail in healthcheckData.UserAccountData.ListFakePwdChangeAllUsers)
            {
                if (!string.IsNullOrEmpty(detail.DistinguishedName))
                {
                    fakePasswordChangeMap[detail.DistinguishedName] = detail;
                }
            }

            // Build a HashSet of privileged member DistinguishedNames to dedupe and report only those with fake password changes
            var reportedDistinguishedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            int reportedCount = 0;

            foreach (var group in healthcheckData.PrivilegedGroups)
            {
                if (group.Members == null)
                {
                    continue;
                }

                foreach (var member in group.Members)
                {
                    if (member.IsExternal)
                    {
                        continue;
                    }

                    if (!member.IsEnabled)
                    {
                        continue;
                    }

                    if (reportedDistinguishedNames.Contains(member.DistinguishedName ?? string.Empty))
                    {
                        continue;
                    }

                    if (fakePasswordChangeMap.TryGetValue(member.DistinguishedName ?? string.Empty, out var fakePasswordDetail))
                    {
                        reportedDistinguishedNames.Add(member.DistinguishedName);
                        AddRawDetail(
                            fakePasswordDetail.Name,
                            fakePasswordDetail.PwdLastSet.ToUniversalTime().ToString("u"),
                            fakePasswordDetail.Event.ToUniversalTime().ToString("u"),
                            "pwdLastSet refreshed without a matching unicodePwd change");
                        reportedCount++;
                    }
                }
            }

            return reportedCount > 0 ? reportedCount : null;
        }
    }
}
