//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace PingCastle.Healthcheck.Rules
{
	[HeatlcheckRuleModel("A-MD5RootCert", HealthcheckRiskRuleCategory.Anomalies, HealthcheckRiskModelCategory.CertificateTakeOver)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnPresence, 0)]
    public class HeatlcheckRuleAnomalyCertMD5Root : HeatlcheckRuleBase
    {
		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            foreach (HealthcheckCertificateData data in healthcheckData.TrustedCertificates)
            {
                X509Certificate2 cert = new X509Certificate2(data.Certificate);
                if (Encoding.Default.GetString(cert.SubjectName.RawData) == Encoding.Default.GetString(cert.IssuerName.RawData))
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
