//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.misc;
using PingCastle.Rules;
using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-CertROCA", RiskRuleCategory.Anomalies, RiskModelCategory.CertificateTakeOver)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 15)]
    [RuleDurANSSI(1, "certificates_vuln", "Weak or vulnerable certificates")]
    [RuleIntroducedIn(2, 9)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.WeakenEncryptionReduceKeySpace)]
    public class HeatlcheckRuleAnomalyCertROCA : RuleBase<HealthcheckData>
    {


        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            foreach (HealthcheckCertificateData data in healthcheckData.TrustedCertificates)
            {
                X509Certificate2 cert = new X509Certificate2(data.Certificate);
                RSA key = null;
                try
                {
                    key = cert.PublicKey.Key as RSA;
                }
                catch (Exception)
                {
                    Trace.WriteLine("Non RSA key detected in certificate");
                }
                if (key != null)
                {
                    RSAParameters rsaparams = key.ExportParameters(false);
                    if (ROCAVulnerabilityTester.IsVulnerable(rsaparams))
                    {
                        AddRawDetail(data.Source, cert.Subject, cert.NotAfter.ToString("u"));
                    }
                }
            }
            if (healthcheckData.DomainControllers != null)
            {
                foreach (var dc in healthcheckData.DomainControllers)
                {
                    if (dc.LDAPCertificate != null && dc.LDAPCertificate.Length > 0)
                    {
                        X509Certificate2 cert = null;
                        RSA key = null;
                        try
                        {
                            cert = new X509Certificate2(dc.LDAPCertificate);
                            key = cert.PublicKey.Key as RSA;
                        }
                        catch (Exception)
                        {
                            Trace.WriteLine("Non RSA key detected in certificate");
                        }
                        if (key != null)
                        {
                            RSAParameters rsaparams = key.ExportParameters(false);
                            if (ROCAVulnerabilityTester.IsVulnerable(rsaparams))
                            {
                                AddRawDetail("DC " + dc.DCName, cert.Subject, cert.NotAfter.ToString("u"));
                            }
                        }
                    }
                }
            }
            return null;
        }
    }
}
