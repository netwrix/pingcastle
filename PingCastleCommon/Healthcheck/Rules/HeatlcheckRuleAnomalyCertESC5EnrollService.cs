//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    /// <summary>
    /// ESC5 (partial) – Vulnerable PKI AD Object: Enrollment Service.
    /// A low-privileged principal has write permissions on a CA's
    /// pKIEnrollmentService AD object in the Configuration partition.
    /// This allows an attacker to add arbitrary certificate templates to the CA's
    /// published list or to perform an object takeover, leading to domain compromise.
    /// Reference: Certified Pre-Owned – ESC5 (SpecterOps).
    /// </summary>
    [RuleModel("A-CertESC5EnrollService", RiskRuleCategory.Anomalies, RiskModelCategory.CertificateTakeOver)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 20)]
    [RuleIntroducedIn(3, 3)]
    [RuleMaturityLevel(2)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.StealorForgeKerberosTickets)]
    public class HeatlcheckRuleAnomalyCertESC5EnrollService : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.CertificateAuthorities == null)
                return null;

            if (!healthcheckData.IsPrivilegedMode)
            {
                Notice = @"<strong>Reduced confidence</strong><br>Use privilege mode for accuracy";
                NoticeTooltip = "This check requires <b>Privilege mode</b> to read enrollment service ACLs. Run PingCastle with <code>--privileged</code> for accurate results.";
            }

            foreach (var ca in healthcheckData.CertificateAuthorities)
            {
                if (ca.VulnerableEnrollmentServiceACL != true)
                    continue;

                if (ca.LowPrivilegedEnrollmentServiceWritePrincipals != null)
                {
                    foreach (var principal in ca.LowPrivilegedEnrollmentServiceWritePrincipals)
                    {
                        AddRawDetail(ca.Name, ca.DnsHostName, principal);
                    }
                }
                else
                {
                    AddRawDetail(ca.Name, ca.DnsHostName, "");
                }
            }

            return null;
        }
    }
}
