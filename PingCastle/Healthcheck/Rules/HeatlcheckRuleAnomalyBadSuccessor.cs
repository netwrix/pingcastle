// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
using System;
using System.Linq;
using System.Collections.Generic;
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-BadSuccessor", RiskRuleCategory.Anomalies, RiskModelCategory.ObjectConfig)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 20)]
    [RuleIntroducedIn(3,0,4)]
    [RuleANSSI("R37", "paragraph.3.6.2.1")]
    [RuleDurANSSI(1, "bad_successor_delegation_detected", "One or more Organizational Units (OUs) in your Active Directory domain have delegations granting non-privileged users or groups the ability to create or control msDS-DelegatedManagedServiceAccount objects")]
    [RuleMitreAttackTechnique(MitreAttackTechnique.AccountManipulation)]
    public class HeatlcheckRuleAnomalyBadSuccessor : RuleBase<HealthcheckData>
    {
        // Collection of rights that are considered risks in this context.
        private readonly HashSet<string> _riskyRights = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "CreateChild (All Objects)",
            "WriteDacl (All Objects)",
            "WriteOwner (All Objects)",
            "GenericAll (All Objects)",
            "GenericAll (Descendant msDS-DelegatedManagedServiceAccount)",
            "WriteDacl (Descendant msDS-DelegatedManagedServiceAccount)",
            "WriteOwner (Descendant msDS-DelegatedManagedServiceAccount)",
            "GenericWrite (Descendant msDS-DelegatedManagedServiceAccount)",
            "WriteProperty (Descendant msDS-DelegatedManagedServiceAccount)",
            "GenericAll (Descendant OUs)",
            "WriteDacl (Descendant OUs)",
            "WriteOwner (Descendant OUs)",
            "CreateChild (Descendant OUs)",
            "CreateChild msDS-DelegatedManagedServiceAccount Objects"
        };


        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            // First two checks for mitigations 2 and 3 from https://specterops.io/blog/2025/05/27/understanding-mitigating-badsuccessor/

            // KDS Root Keys - no KDS Root Key, no further checks required
            if (!healthcheckData.HasKdsRootKey)
            {
                return null;
            }

            // Check for at least one Windows Server 2025 DC
            if (!healthcheckData.DomainControllers.Any(dc => dc.OperatingSystem == "Windows 2025"))
            {
                return null;
            }

            // Prepare privileged users and groups for filtering
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
            healthcheckData.AllPrivilegedMembers?.ForEach(member =>
            {
                if (!string.IsNullOrEmpty(member.Sid))
                    privilegedMembers.Add(member.Sid);
            });

            // Find OU delegations that include the BadSuccessor permissions
            var findings = new List<(string Principal, string Permission, string OU)>();
            if (healthcheckData.Delegations != null)
            {
                var appropriateDelegations = healthcheckData.Delegations
                    .Where(d => !string.IsNullOrEmpty(d.DistinguishedName) && !string.IsNullOrEmpty(d.Right));

                foreach (var delegation in appropriateDelegations)
                {
                    // Skip privileged users and groups
                    if (privilegedGroups.Contains(delegation.SecurityIdentifier) ||
                        privilegedMembers.Contains(delegation.SecurityIdentifier))
                        continue;

                    // Skip if the OU is under CN=System or starts with "CN="
                    if (delegation.DistinguishedName.Contains("CN=System,DC=")
                        || delegation.DistinguishedName.StartsWith("CN="))
                    {
                        continue;
                    }

                    // Principal display as DOMAIN\SAMACCOUNTNAME if possible
                    string principalDisplay = !string.IsNullOrEmpty(delegation.Account)
                        ? delegation.Account
                        : (!string.IsNullOrEmpty(delegation.SecurityIdentifier)
                            ? delegation.SecurityIdentifier
                            : "(unknown)");

                    // delegation.Right is in the form of "WriteDacl,WriteOwner" etc.
                    // Split and then add a row for each specific permission found
                    var rights = delegation.Right.Split(',').Select(r => r.Trim());

                    // Check for risky permissions
                    foreach (var right in rights)
                    {
                        if (_riskyRights.Contains(right))
                        {
                            findings.Add((principalDisplay, right, delegation.DistinguishedName));
                        }
                    }
                }
            }

            if (findings.Count == 0)
            {
                return null;
            }

            // Report Findings
            foreach (var f in findings)
            {
                AddRawDetail(f.Principal, f.Permission, f.OU);
            }

            return findings.Count;
        }
    }
}