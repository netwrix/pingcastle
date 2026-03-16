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
    /// Certificate template requires Key Recovery Agent (KRA) archival.
    /// When bit 0x4000 of msPKI-Private-Key-Flag is set the CA archives the enrollee's
    /// private key, encrypted to the configured Key Recovery Agent certificate(s).
    /// Any principal who holds a KRA certificate and its private key can decrypt and
    /// recover ALL private keys archived under that CA — past and present — making the
    /// KRA a high-value target. If the KRA account is compromised, all historical
    /// encryption traffic protected by archived keys can be decrypted retroactively.
    /// Templates that allow low-privilege enrollment with key archival amplify the risk.
    /// Reference: Microsoft PKI Design Guidance; AD CS Attack and Defense (SpecterOps).
    /// </summary>
    [RuleModel("A-CertTemplateKeyArchival", RiskRuleCategory.Anomalies, RiskModelCategory.CertificateTakeOver)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 10)]
    [RuleIntroducedIn(3, 3)]
    [RuleMaturityLevel(2)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.StealorForgeKerberosTickets)]
    public class HeatlcheckRuleAnomalyCertTemplateKeyArchival : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.CertificateTemplates == null)
                return null;

            foreach (var ct in healthcheckData.CertificateTemplates)
            {
                if (!ct.RequiresKeyArchival)
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
