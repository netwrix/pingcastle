//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;
using System.Collections.Generic;
using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-CertTempCustomSubject", RiskRuleCategory.Anomalies, RiskModelCategory.CertificateTakeOver)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 15)]
    [RuleIntroducedIn(2, 9, 3)]
    [RuleDurANSSI(1, "adcs_template_auth_enroll_with_name", "Dangerous enrollment permission on authentication certificate templates")]
    [RuleMitreAttackTechnique(MitreAttackTechnique.StealorForgeKerberosTickets)]
    public class HeatlcheckRuleAnomalyCertTempCustomSubject : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.CertificateTemplates != null)
            {
                var trustedCAsThumbprints = healthcheckData.TrustedCertificates
                    .Where(c => c.Store == "NTLMStore" && c.Certificate?.Length > 0)
                    .Select(c => new X509Certificate2(c.Certificate).Thumbprint)
                    .ToHashSet();

                var caCertificates = new Dictionary<string, X509Certificate2>();
                var allCAs = new Dictionary<string, HealthCheckCertificateAuthorityData>();
                foreach (var ca in healthcheckData.CertificateAuthorities)
                {
                    var validCertificates = ca.CertificatesData
                       .Select(d => new X509Certificate2(d))
                       .Where(cert => cert.NotBefore < DateTime.Now && DateTime.Now < cert.NotAfter)
                       .ToList();

                    var actualCertificate = validCertificates.OrderByDescending(c => c.NotAfter).FirstOrDefault();
                    caCertificates[ca.FullName] = actualCertificate;
                    allCAs[ca.FullName] = ca;
                }

                var extraDetailIndex = 0;
                foreach (var ct in healthcheckData.CertificateTemplates)
                {
                    foreach (var caName in ct.CA)
                    {
                        var caCertificate = caCertificates[caName];
                        if (!trustedCAsThumbprints.Contains(caCertificate?.Thumbprint))
                            continue;

                        if (!ct.CAManagerApproval && ct.IssuanceRequirementsEmpty && ct.LowPrivCanEnroll && ct.HasAuthenticationEku 
                            && ct.EnrolleeSupplies > 0 && ct.EnrollmentLowPrivilegePrincipals.Count > 0)
                        {
                            var principals = string.Join(";", ct.EnrollmentLowPrivilegePrincipals);

                            AddRawDetail(extraDetailIndex++, ct.Name, extraDetailIndex++, caName, principals, ct.WhenChanged);

                            AddExtraDetail(BuildTooltipDataForName(ct));
                            AddExtraDetail(BuildTooltipDataForCA(allCAs[caName]));
                        }
                    }
                }
            }
            return null;
        }

        private ExtraDetail BuildTooltipDataForName(HealthCheckCertificateTemplate ct)
        {
            var detail = new ExtraDetail()
            .AddTextItem("Schema Version", ct.SchemaVersion.ToString())
            .AddListItem("EKUs", ct.EKUs)
            .AddTextItem("Authorized signatures required", ct.IsAuthorisedSignaturesRequired.ToString())
            .AddTextItem("Owner", ct.Owner)
            .AddListItem("Permissions", ct.Rights.Select(r => $"{r.Account}->{string.Join("|", r.Rights)}"));

            return detail;
        }

        private ExtraDetail BuildTooltipDataForCA(HealthCheckCertificateAuthorityData ca)
        {
            var detail = new ExtraDetail()
           .AddTextItem("Hostname", ca.Name);

            if (ca.LowPrivelegedEnrollPrincipals != null)
                detail.AddListItem("Enrollment rights", ca.LowPrivelegedEnrollPrincipals);

            if(ca.LowPrivelegedManagerPrincipals != null)
                detail.AddListItem("CA Managers", ca.LowPrivelegedManagerPrincipals);

            if (ca.EnrollmentRestrictions != null)
                detail.AddTextItem("Enrollment Restrictions", ca.EnrollmentRestrictions);

            return detail;
        }
    }
}
