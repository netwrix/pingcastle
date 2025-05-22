// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
using System;
using System.Linq;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Security.Principal;
using PingCastle.Rules;
using PingCastle.Healthcheck.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-BadSuccessor", RiskRuleCategory.Anomalies, RiskModelCategory.ObjectConfig)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 20)]
    public class HeatlcheckRuleAnomalyBadSuccessor : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            // 1. Check for at least one Windows Server 2025 DC
            bool has2025DC = false;
            foreach (var dc in healthcheckData.DomainControllers)
            {
                if (dc.OperatingSystem == "Windows 2025")
                {
                    has2025DC = true;
                    break;
                }
            }
            if (!has2025DC)
                return null;

            // 2. Prepare privileged users and groups for filtering
            var privilegedGroups = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (healthcheckData.PrivilegedGroups != null)
            {
                foreach (var group in healthcheckData.PrivilegedGroups)
                {
                    if (!string.IsNullOrEmpty(group.Sid))
                        privilegedGroups.Add(group.Sid);
                }
            }
            var privilegedMembers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (healthcheckData.AllPrivilegedMembers != null)
            {
                foreach (var member in healthcheckData.AllPrivilegedMembers)
                {
                    if (!string.IsNullOrEmpty(member.Sid))
                        privilegedMembers.Add(member.Sid);
                }
            }


            // 3. Find OU delegations that include the BadSuccessor permissions
            var findings = new List<(string Principal, string Permission, string OU)>();
            if (healthcheckData.Delegations != null)
            {
                foreach (var delegation in healthcheckData.Delegations)
                {
                    // Skip privileged users and groups
                    if (privilegedGroups.Contains(delegation.SecurityIdentifier) ||
                        privilegedMembers.Contains(delegation.SecurityIdentifier))
                        continue;

                    // Skip if the OU is under CN=System or starts with "CN="
                    if (!string.IsNullOrEmpty(delegation.DistinguishedName) && (delegation.DistinguishedName.Contains("CN=System,DC=") || delegation.DistinguishedName.StartsWith("CN=")))
                        continue;

                    // Principal display as DOMAIN\SAMACCOUNTNAME if possible
                    string principalDisplay = !string.IsNullOrEmpty(delegation.Account)
                        ? delegation.Account
                        : (!string.IsNullOrEmpty(delegation.SecurityIdentifier) ? delegation.SecurityIdentifier : "(unknown)");

                    // Check for risky permissions
                    var riskyRights = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                    {
                        "CreateChild (All Objects)",
                        "WriteDacl (All Objects)",
                        "WriteOwner (All Objects)",
                        "GenericAll (All Objects)",
                        "GenericAll (msDS-DelegatedManagedServiceAccount)",
                        "WriteDacl (msDS-DelegatedManagedServiceAccount)",
                        "WriteOwner (msDS-DelegatedManagedServiceAccount)",
                        "CreateChild (msDS-DelegatedManagedServiceAccount)"
                    };

                    // delegation.Right is in the form of "WriteDacl,WriteOwner" etc.
                    // Split and then add a row for each specific permission found
                    if (!string.IsNullOrEmpty(delegation.Right))
                    {
                        var rights = delegation.Right.Split(',').Select(r => r.Trim());

                        foreach (var right in rights)
                        {
                            if (riskyRights.Contains(right))
                            {
                                findings.Add((principalDisplay, right, delegation.DistinguishedName));
                            }
                        }
                    }
                }
            }
            if (findings.Count == 0)
                return null;

            // Report Findings
            foreach (var f in findings)
            {
                AddRawDetail(f.Principal, f.Permission, f.OU);
            }
            return findings.Count;
        }
    }
}