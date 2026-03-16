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
    /// ESC13 – OID Group Link on Certificate Template.
    /// A certificate template has an issuance policy (msPKI-Certificate-Policy) that is
    /// linked to a security group via the msDS-OIDToGroupLink attribute on the OID object.
    /// When a user receives a certificate issued from such a template, their Kerberos ticket
    /// will include the linked group's SID, effectively granting them membership of that group.
    /// If the linked group has elevated privileges, a low-privileged user who can enroll on
    /// this template gains those privileges at logon time.
    /// Reference: Certified Pre-Owned – ESC13 (SpecterOps).
    /// </summary>
    [RuleModel("A-CertESC13OIDGroupLink", RiskRuleCategory.Anomalies, RiskModelCategory.CertificateTakeOver)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 15)]
    [RuleIntroducedIn(3, 3)]
    [RuleMaturityLevel(2)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.StealorForgeKerberosTickets)]
    public class HeatlcheckRuleAnomalyCertESC13OIDGroupLink : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.CertificateTemplates == null)
                return null;

            foreach (var ct in healthcheckData.CertificateTemplates)
            {
                if (string.IsNullOrEmpty(ct.LinkedOIDGroup))
                    continue;

                // Only flag if low-privileged users can actually enroll
                if (!ct.LowPrivCanEnroll)
                    continue;

                AddRawDetail(ct.Name, ct.LinkedOIDGroup);
            }

            return null;
        }
    }
}
