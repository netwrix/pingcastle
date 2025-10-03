//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-WeakRSARootCert", RiskRuleCategory.Anomalies, RiskModelCategory.CertificateTakeOver)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 5)]
    [RuleSTIG("V-14820", "PKI certificates (server and clients) must be issued by the DoD PKI or an approved External Certificate Authority (ECA).", STIGFramework.ActiveDirectoryService2003)]
    [RuleDurANSSI(1, "certificates_vuln", "Weak or vulnerable certificates")]
    [RuleMitreAttackTechnique(MitreAttackTechnique.WeakenEncryptionReduceKeySpace)]
    public class HeatlcheckRuleAnomalyCertWeakRSA : RuleBase<HealthcheckData>
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
                        if (rsaparams.Modulus.Length * 8 < 1024)
                        {
                            Trace.WriteLine("Modulus len = " + rsaparams.Modulus.Length * 8);
                            AddRawDetail(data.Source, cert.Subject, rsaparams.Modulus.Length * 8, cert.NotAfter);
                        }
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
                            {
                                if (rsaparams.Modulus.Length * 8 < 1024)
                                {
                                    Trace.WriteLine("Modulus len = " + rsaparams.Modulus.Length * 8);
                                    AddRawDetail("DC " + dc.DCName, cert.Subject, rsaparams.Modulus.Length * 8, cert.NotAfter);
                                }
                            }
                        }
                    }
                }
            }
            if (healthcheckData.GPOWSUS != null)
            {
                var WSUSCache = new List<string>();
                foreach (var wsus in healthcheckData.GPOWSUS)
                {
                    if (wsus.WSUSserverCertificate != null && wsus.WSUSserverCertificate.Length > 0 
                        && !string.IsNullOrEmpty(wsus.WSUSserver) && !WSUSCache.Contains(wsus.WSUSserver))
                    {
                        WSUSCache.Add(wsus.WSUSserver);
                        X509Certificate2 cert = null;
                        RSA key = null;
                        try
                        {
                            cert = new X509Certificate2(wsus.WSUSserverCertificate);
                            key = cert.PublicKey.Key as RSA;
                        }
                        catch (Exception)
                        {
                            Trace.WriteLine("Non RSA key detected in certificate");
                        }
                        if (key != null)
                        {
                            RSAParameters rsaparams = key.ExportParameters(false);
                            if (rsaparams.Modulus.Length * 8 < 1024)
                            {
                                AddRawDetail("WSUS " + wsus.WSUSserver, cert.Subject, rsaparams.Modulus.Length * 8, cert.NotAfter.ToString("u"));
                            }
                        }
                    }
                    if (wsus.WSUSserverAlternateCertificate != null && wsus.WSUSserverAlternateCertificate.Length > 0 
                        && !string.IsNullOrEmpty(wsus.WSUSserverAlternate) && !WSUSCache.Contains(wsus.WSUSserverAlternate))
                    {
                        WSUSCache.Add(wsus.WSUSserverAlternate);
                        X509Certificate2 cert = null;
                        RSA key = null;
                        try
                        {
                            cert = new X509Certificate2(wsus.WSUSserverAlternateCertificate);
                            key = cert.PublicKey.Key as RSA;
                        }
                        catch (Exception)
                        {
                            Trace.WriteLine("Non RSA key detected in certificate");
                        }
                        if (key != null)
                        {
                            RSAParameters rsaparams = key.ExportParameters(false);
                            if (rsaparams.Modulus.Length * 8 < 1024)
                            {
                                AddRawDetail("WSUS " + wsus.WSUSserverAlternate, cert.Subject, rsaparams.Modulus.Length * 8, cert.NotAfter.ToString("u"));
                            }
                        }
                    }
                }
            }
            return null;
        }
    }
}
