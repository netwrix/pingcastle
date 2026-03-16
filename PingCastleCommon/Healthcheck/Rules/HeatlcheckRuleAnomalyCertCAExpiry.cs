//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    /// <summary>
    /// CA certificate is expiring within 90 days (or already expired).
    /// When the CA's own certificate expires, it can no longer issue new certificates
    /// and all certificates signed by it may be treated as invalid by relying parties.
    /// An expired CA certificate causes authentication failures (Kerberos PKINIT,
    /// smart card logon, LDAPS), broken TLS chains, and halted PKI operations.
    /// Recovery requires re-issuing the CA certificate and re-enrolling all issued certs,
    /// which is operationally disruptive in large environments.
    /// This rule warns when expiry is within 90 days to allow timely renewal.
    /// </summary>
    [RuleModel("A-CertCAExpiry", RiskRuleCategory.Anomalies, RiskModelCategory.CertificateTakeOver)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 20)]
    [RuleIntroducedIn(3, 3)]
    [RuleMaturityLevel(1)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.StealorForgeKerberosTickets)]
    public class HeatlcheckRuleAnomalyCertCAExpiry : RuleBase<HealthcheckData>
    {
        private const int WarningDaysBeforeExpiry = 90;

        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.CertificateAuthorities == null)
                return null;

            var threshold = DateTime.UtcNow.AddDays(WarningDaysBeforeExpiry);

            foreach (var ca in healthcheckData.CertificateAuthorities)
            {
                if (ca.CertificateExpiryDate == null)
                    continue;

                if (ca.CertificateExpiryDate.Value.ToUniversalTime() <= threshold)
                {
                    var daysLeft = (int)(ca.CertificateExpiryDate.Value.ToUniversalTime() - DateTime.UtcNow).TotalDays;
                    AddRawDetail(ca.Name, ca.DnsHostName, ca.CertificateExpiryDate.Value.ToString("yyyy-MM-dd"), daysLeft < 0 ? "EXPIRED" : $"{daysLeft} days left");
                }
            }

            return null;
        }
    }
}
