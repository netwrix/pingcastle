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
    /// Certificate template has an excessively long validity period (&gt;5 years).
    /// Long-lived certificates issued on low-privilege-enrollable templates extend the
    /// window of opportunity for an attacker who obtains a certificate: revocation may
    /// not be checked, certificates may outlive account disablement, and stolen certs
    /// remain valid for authentication far beyond their operational need.
    /// Best practice (NIST SP 800-57, CIS AD CS Benchmark) recommends:
    ///   ≤ 1 year  for user/computer authentication templates
    ///   ≤ 2 years for code signing
    ///   ≤ 5 years for CA certificates
    /// This rule flags templates available to low-privileged users with validity &gt; 5 years.
    /// </summary>
    [RuleModel("A-CertTemplateLongValidity", RiskRuleCategory.Anomalies, RiskModelCategory.CertificateTakeOver)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 5)]
    [RuleIntroducedIn(3, 3)]
    [RuleMaturityLevel(2)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.StealorForgeKerberosTickets)]
    public class HeatlcheckRuleAnomalyCertTemplateLongValidity : RuleBase<HealthcheckData>
    {
        // 5 years * 365 days
        private const int ThresholdDays = 1825;

        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.CertificateTemplates == null)
                return null;

            foreach (var ct in healthcheckData.CertificateTemplates)
            {
                if (ct.ValidityPeriodDays <= ThresholdDays)
                    continue;

                if (!ct.LowPrivCanEnroll)
                    continue;

                if (ct.CAManagerApproval)
                    continue;

                if (!ct.IssuanceRequirementsEmpty)
                    continue;

                AddRawDetail(ct.Name, ct.ValidityPeriodDays.ToString());
            }

            return null;
        }
    }
}
