// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-DnsHostnameMismatch", RiskRuleCategory.Anomalies, RiskModelCategory.CertificateTakeOver)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 10)]
    [RuleIntroducedIn(4, 0, 1)]
    [RuleMaturityLevel(1)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.StealorForgeAuthenticationCertificates)]
    public class HeatlcheckRuleAnomalyDnsHostnameMismatch : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.DnsHostnameMismatches == null || healthcheckData.DnsHostnameMismatches.Count == 0)
            {
                return null;
            }

            foreach (var m in healthcheckData.DnsHostnameMismatches)
            {
                AddRawDetail(m.DistinguishedName, m.SAMAccountName, m.DNSHostName, m.WhenCreated);
            }

            return healthcheckData.DnsHostnameMismatches.Count;
        }
    }
}
