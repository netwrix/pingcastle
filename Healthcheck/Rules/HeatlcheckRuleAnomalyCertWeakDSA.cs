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
    [RuleModel("A-CertWeakDSA", RiskRuleCategory.Anomalies, RiskModelCategory.CertificateTakeOver)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 0)]
    [RuleDurANSSI(1, "certificates_vuln", "Weak or vulnerable certificates")]
    [RuleIntroducedIn(2, 9)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.WeakenEncryptionReduceKeySpace)]
    public class HeatlcheckRuleAnomalyCertWeakDSA : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            foreach (HealthcheckCertificateData data in healthcheckData.TrustedCertificates)
            {
                X509Certificate2 cert = new X509Certificate2(data.Certificate);
                DSA key = null;
                try
                {
                    key = cert.PublicKey.Key as DSA;
                }
                catch (Exception)
                {
                    Trace.WriteLine("Non DSA key detected in certificate");
                }
                if (key != null)
                {
                    foreach (X509Extension extension in cert.Extensions)
                    {
                        if (extension.Oid.FriendlyName == "Key Usage")
                        {
                            var ext = (X509KeyUsageExtension)extension;
                            if ((ext.KeyUsages & X509KeyUsageFlags.DigitalSignature) != 0)
                            {
                                AddRawDetail(data.Source, cert.Subject);
                            }
                            break;
                        }
                    }
                }
            }
            return null;
        }
    }
}
