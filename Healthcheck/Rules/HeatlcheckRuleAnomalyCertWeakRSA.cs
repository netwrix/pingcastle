//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace PingCastle.Healthcheck.Rules
{
	[HeatlcheckRuleModel("A-WeakRSARootCert", HealthcheckRiskRuleCategory.Anomalies, HealthcheckRiskModelCategory.CertificateTakeOver)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnPresence, 5)]
    public class HeatlcheckRuleAnomalyCertWeakRSA : HeatlcheckRuleBase
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
                catch(Exception)
                {
                    Trace.WriteLine("Non RSA key detected in certificate");
                }
                if (key != null)
                {
                    RSAParameters rsaparams = key.ExportParameters(false);
                    {
                        if (rsaparams.Modulus.Length * 8 < 1024)
                        {
                            Trace.WriteLine("Modulus len = " + rsaparams.Exponent.Length * 8);
							AddRawDetail(data.Source, cert.Subject, rsaparams.Exponent.Length * 8); 
                        }
                    }
                }
            }
            return null;
        }
    }
}
