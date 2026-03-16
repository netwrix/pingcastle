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
    /// ESC5 (partial) – Vulnerable PKI AD Object: NTAuthCertificates.
    /// A low-privileged principal has write permissions on the
    /// CN=NTAuthCertificates object in the Configuration partition.
    /// This allows an attacker to add a rogue CA certificate to the enterprise
    /// trusted CA store, enabling arbitrary authentication certificates to be
    /// accepted by domain-joined systems.
    /// Reference: Certified Pre-Owned – ESC5 (SpecterOps).
    /// </summary>
    [RuleModel("A-CertESC5NTAuth", RiskRuleCategory.Anomalies, RiskModelCategory.CertificateTakeOver)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 20)]
    [RuleIntroducedIn(3, 3)]
    [RuleMaturityLevel(2)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.StealorForgeKerberosTickets)]
    public class HeatlcheckRuleAnomalyCertESC5NTAuth : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.NTAuthCertificatesVulnerableACL != true)
                return null;

            if (!healthcheckData.IsPrivilegedMode)
            {
                Notice = @"<strong>Reduced confidence</strong><br>Use privilege mode for accuracy";
                NoticeTooltip = "This check requires <b>Privilege mode</b> to read NTAuthCertificates ACL. Run PingCastle with <code>--privileged</code> for accurate results.";
            }

            if (healthcheckData.NTAuthCertificatesLowPrivWritePrincipals != null)
            {
                foreach (var principal in healthcheckData.NTAuthCertificatesLowPrivWritePrincipals)
                {
                    AddRawDetail(principal);
                }
            }

            return null;
        }
    }
}
