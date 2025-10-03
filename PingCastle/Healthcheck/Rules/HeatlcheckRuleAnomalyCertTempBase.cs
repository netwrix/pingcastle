namespace PingCastle.Healthcheck.Rules
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using PingCastle.Rules;

    public abstract class HeatlcheckRuleAnomalyCertTempBase : RuleBase<HealthcheckData>
    {
        protected abstract bool IsVulnerable(HealthCheckCertificateTemplate template);

        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.CertificateTemplates == null)
                return null;

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

            if (!healthcheckData.IsPrivilegedMode)
                AddNotice();

            var extraDetailIndex = 0;
            foreach (var ct in healthcheckData.CertificateTemplates)
            {
                foreach (var caName in ct.CA)
                {
                    var caCertificate = caCertificates[caName];
                    if (!trustedCAsThumbprints.Contains(caCertificate?.Thumbprint))
                        continue;

                    var ca = allCAs[caName];

                    var isCaVulnerable = !healthcheckData.IsPrivilegedMode || (healthcheckData.IsPrivilegedMode && ca.LowPrivelegedEnrollPrincipals?.Count > 0);

                    if (isCaVulnerable && IsVulnerable(ct))
                    {
                        var principals = string.Join(";", ct.EnrollmentLowPrivilegePrincipals);

                        AddRawDetail(extraDetailIndex++, ct.Name, extraDetailIndex++, caName, principals, ct.WhenChanged);

                        AddExtraDetail(BuildTooltipDataForName(ct));
                        AddExtraDetail(BuildTooltipDataForCA(ca));
                    }
                }
            }

            return null;
        }

        private void AddNotice()
        {
            Notice = @"<strong>Reduced confidence</strong><br>Use privilege mode for accuracy";

            var tooltip = new StringBuilder();
            tooltip.Append("This check ran without <b>Privilege mode</b>.")
                   .Append("<br>The issue is likely real, but some supporting data couldn't be verified.")
                   .Append("<br> For better accuracy:<ul>")
                   .Append(@"<li>Use <span class='border-flag'><code>--privileged</code></span> command line argument</li>")
                   .Append("<li>Or select <b>Yes</b> when prompted during interactive scans.</li></ul>");

            NoticeTooltip = tooltip.ToString();
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

            if (ca.LowPrivelegedManagerPrincipals != null)
                detail.AddListItem("CA Managers", ca.LowPrivelegedManagerPrincipals);

            if (ca.EnrollmentRestrictions != null)
                detail.AddTextItem("Enrollment Restrictions", ca.EnrollmentRestrictions);

            return detail;
        }
    }
}
