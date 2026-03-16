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
    /// Certificate template allows exportable private keys (CT_FLAG_EXPORTABLE_KEY).
    /// When bit 0x10 of msPKI-Private-Key-Flag is set the CA generates a key pair whose
    /// private key can be exported from the Windows certificate store (e.g. via certmgr.msc,
    /// Mimikatz, or crypto API calls). A low-privileged enrollee can therefore obtain a
    /// certificate AND its private key, enabling long-term credential theft even after
    /// the original certificate is revoked if the private key is kept.
    /// Risk is highest when the template also supports authentication EKUs and low-privilege
    /// enrollment (combining ESC1-class capability with key exfiltration).
    /// </summary>
    [RuleModel("A-CertTemplateExportableKey", RiskRuleCategory.Anomalies, RiskModelCategory.CertificateTakeOver)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 5)]
    [RuleIntroducedIn(3, 3)]
    [RuleMaturityLevel(2)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.StealorForgeKerberosTickets)]
    public class HeatlcheckRuleAnomalyCertTemplateExportableKey : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.CertificateTemplates == null)
                return null;

            foreach (var ct in healthcheckData.CertificateTemplates)
            {
                if (!ct.ExportableKey)
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
