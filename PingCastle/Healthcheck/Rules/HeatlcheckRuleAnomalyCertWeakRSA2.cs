//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;
using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-WeakRSARootCert2", RiskRuleCategory.Anomalies, RiskModelCategory.CertificateTakeOver)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 1)]
    [RuleSTIG("V-14820", "PKI certificates (server and clients) must be issued by the DoD PKI or an approved External Certificate Authority (ECA).", STIGFramework.ActiveDirectoryService2003)]
    [RuleDurANSSI(3, "certificates_vuln", "Weak or vulnerable certificates")]
    [RuleIntroducedIn(2, 9)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.WeakenEncryptionReduceKeySpace)]
    public class HeatlcheckRuleAnomalyCertWeakRSA2 : RuleBase<HealthcheckData>
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
                    {
                        if (rsaparams.Modulus.Length * 8 >= 1024)
                        {
                            if (rsaparams.Modulus.Length * 8 < 2048)
                            {
                                Trace.WriteLine("Modulus len = " + rsaparams.Modulus.Length * 8);
                                AddRawDetail(data.Source, cert.Subject, rsaparams.Modulus.Length * 8, cert.NotAfter.ToString("u"));
                            }
                            else if (rsaparams.Modulus.Length * 8 < 3072 && cert.NotAfter > new DateTime(2031, 01, 01))
                            {
                                Trace.WriteLine("Modulus len = " + rsaparams.Modulus.Length * 8);
                                AddRawDetail(data.Source, cert.Subject, rsaparams.Modulus.Length * 8, cert.NotAfter.ToString("u"));
                            }
                        }
                    }
                }
            }
            return null;
        }
    }
}
