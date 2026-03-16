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
    /// ESC15 – EKUwu / Arbitrary Application Policy Injection (CVE-2024-49019).
    /// Schema Version 1 certificate templates do not bind the Application Policy
    /// extension from the CA configuration; instead, the CA accepts Application
    /// Policies supplied by the enrollee in the Certificate Signing Request (CSR).
    /// An attacker who can enroll on such a template can inject any Application
    /// Policy (e.g. Client Authentication, Smart Card Logon) into the issued
    /// certificate — even if the template does not have that EKU configured —
    /// enabling authentication as the requesting user with elevated capabilities.
    /// Affected templates require no manager approval and no authorised signatures,
    /// so any low-privileged enrollee can exploit this.
    /// Mitigation: Apply the November 2024 Windows patch (KB5044284 / KB5044277)
    /// and set the template to Schema Version 2 or higher.
    /// Reference: EKUwu research (TrustedSec / Oliver Lyak), CVE-2024-49019.
    /// </summary>
    [RuleModel("A-CertESC15EKUwu", RiskRuleCategory.Anomalies, RiskModelCategory.CertificateTakeOver)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 15)]
    [RuleIntroducedIn(3, 3)]
    [RuleMaturityLevel(2)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.StealorForgeKerberosTickets)]
    public class HeatlcheckRuleAnomalyCertESC15EKUwu : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.CertificateTemplates == null)
                return null;

            foreach (var ct in healthcheckData.CertificateTemplates)
            {
                // Schema Version 1 templates allow the enrollee to supply Application Policies
                // via the CSR, overriding the EKU defined on the template.
                if (ct.SchemaVersion != 1)
                    continue;

                if (!ct.LowPrivCanEnroll)
                    continue;

                if (ct.CAManagerApproval)
                    continue;

                if (!ct.IssuanceRequirementsEmpty)
                    continue;

                AddRawDetail(ct.Name);
            }

            return null;
        }
    }
}
