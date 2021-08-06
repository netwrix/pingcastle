//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-MD5IntermediateCert", RiskRuleCategory.Anomalies, RiskModelCategory.CertificateTakeOver)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 5)]
    [RuleSTIG("V-14820", "PKI certificates (server and clients) must be issued by the DoD PKI or an approved External Certificate Authority (ECA).", STIGFramework.ActiveDirectoryService2003)]
    [RuleDurANSSI(3, "certificates_vuln", "Weak or vulnerable certificates")]
    [RuleMitreAttackTechnique(MitreAttackTechnique.WeakenEncryptionReduceKeySpace)]
    public class HeatlcheckRuleAnomalyCertMD5Intermediate : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            foreach (HealthcheckCertificateData data in healthcheckData.TrustedCertificates)
            {
                X509Certificate2 cert = new X509Certificate2(data.Certificate);
                if (Encoding.Default.GetString(cert.SubjectName.RawData) != Encoding.Default.GetString(cert.IssuerName.RawData))
                {
                    if (cert.SignatureAlgorithm.FriendlyName == "md5RSA")
                    {
                        AddRawDetail(data.Source, cert.Subject);
                    }
                }
            }
            return null;
        }
    }
}
