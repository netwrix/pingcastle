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
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
	[RuleModel("A-MD4IntermediateCert", RiskRuleCategory.Anomalies, RiskModelCategory.CertificateTakeOver)]
	[RuleComputation(RuleComputationType.TriggerOnPresence, 10)]
    public class HeatlcheckRuleAnomalyCertMD4Intermediate : RuleBase<HealthcheckData>
    {
		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            foreach (HealthcheckCertificateData data in healthcheckData.TrustedCertificates)
            {
                X509Certificate2 cert = new X509Certificate2(data.Certificate);
                if (Encoding.Default.GetString(cert.SubjectName.RawData) != Encoding.Default.GetString(cert.IssuerName.RawData))
                {
                    if (cert.SignatureAlgorithm.FriendlyName == "md4RSA")
                    {
						AddRawDetail(data.Source, cert.Subject);
                    }
                }
            }
            return null;
        }
    }
}
