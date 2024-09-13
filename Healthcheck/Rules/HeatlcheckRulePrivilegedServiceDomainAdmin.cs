using PingCastle.Graph.Reporting;
//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;
using System;
using System.Diagnostics;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("P-ServiceDomainAdmin", RiskRuleCategory.PrivilegedAccounts, RiskModelCategory.PrivilegeControl)]
    [RuleComputation(RuleComputationType.TriggerOnThreshold, 15, Threshold: 2)]
    [RuleSTIG("V-36432", "Membership to the Domain Admins group must be restricted to accounts used only to manage the Active Directory domain and domain controllers.")]
    [RuleANSSI("R11", "subsection.2.5")]
    [RuleDurANSSI(1, "dont_expire_priv", "Privileged accounts with never-expiring passwords")]
    [RuleMitreAttackMitigation(MitreAttackMitigation.PrivilegedAccountManagement)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.OSCredentialDumpingLSASecrets)]
    public class HeatlcheckRulePrivilegedServiceDomainAdmin : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            HealthCheckGroupData domainadmins = null;
            foreach (HealthCheckGroupData group in healthcheckData.PrivilegedGroups)
            {
                if (group.GroupName == GraphObjectReference.DomainAdministrators)
                {
                    domainadmins = group;
                    break;
                }
            }
            if (domainadmins == null)
            {
                Trace.WriteLine("Group domain admins not found");
                return 0;
            }
            if (domainadmins.Members == null)
            {
                return domainadmins.NumberOfMemberPwdNeverExpires;
            }
            int countexception = 0;
            foreach (var member in domainadmins.Members)
            {
                if (member.DoesPwdNeverExpires)
                {
                    if (member.PwdLastSet > DateTime.Now.AddDays(-30))
                    {
                        Trace.WriteLine("Rule for pwd last set disable because password changed recently for " + member.Name);
                        countexception++;
                    }
                    else
                    {
                        AddRawDetail(member.DistinguishedName);
                    }
                }
            }
            return null;
        }
    }
}
