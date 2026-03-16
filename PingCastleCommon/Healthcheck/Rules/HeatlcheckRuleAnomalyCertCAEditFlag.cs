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
    /// ESC6 – EDITF_ATTRIBUTESUBJECTALTNAME2 enabled on Certificate Authority.
    /// When this CA flag is set, any user may include an arbitrary Subject Alternative Name (SAN)
    /// in a certificate request, even for templates that do not normally allow it.
    /// Combined with a template that allows low-privileged enrollment, this enables
    /// an attacker to request a certificate for any user (including Domain Admins) and
    /// authenticate as that user via PKINIT / Schannel.
    /// Reference: Certified Pre-Owned – ESC6 (SpecterOps).
    /// </summary>
    [RuleModel("A-CertCAEditFlag", RiskRuleCategory.Anomalies, RiskModelCategory.CertificateTakeOver)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 15)]
    [RuleIntroducedIn(3, 3)]
    [RuleMaturityLevel(2)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.StealorForgeKerberosTickets)]
    public class HeatlcheckRuleAnomalyCertCAEditFlag : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.CertificateAuthorities == null)
                return null;

            if (!healthcheckData.IsPrivilegedMode)
            {
                Notice = @"<strong>Reduced confidence</strong><br>Use privilege mode for accuracy";
                NoticeTooltip = "This check requires <b>Privilege mode</b> to read the CA registry. Run PingCastle with <code>--privileged</code> for accurate results.";
            }

            foreach (var ca in healthcheckData.CertificateAuthorities)
            {
                if (ca.HasSubjectAltNameFlag == true)
                {
                    AddRawDetail(ca.Name, ca.DnsHostName);
                }
            }

            return null;
        }
    }
}
