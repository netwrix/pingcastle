//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;
using System.Collections.Generic;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-WSUS-SslProtocol", RiskRuleCategory.Anomalies, RiskModelCategory.CertificateTakeOver)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 5)]
    [RuleIntroducedIn(2, 10, 1)]
    [RuleMaturityLevel(3)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.WeakenEncryptionReduceKeySpace)]
    public class HeatlcheckRuleAnomalyWSUSSSL : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            var cache = new List<string>();
            if (healthcheckData.GPOWSUS != null)
            {
                foreach (var gpo in healthcheckData.GPOWSUS)
                {
                    if (!string.IsNullOrEmpty(gpo.WSUSserver) && !cache.Contains(gpo.WSUSserver)
                        && gpo.WSUSserverSSLProtocol != null)
                    {
                        cache.Add(gpo.WSUSserver);
                        foreach (var protocol in gpo.WSUSserverSSLProtocol)
                        {
                            switch (protocol)
                            {
                                case "Ssl2":
                                case "Ssl3":
                                    AddRawDetail(gpo.WSUSserver, protocol);
                                    break;
                            }
                        }
                    }
                    if (!string.IsNullOrEmpty(gpo.WSUSserverAlternate) && !cache.Contains(gpo.WSUSserverAlternate)
                        && gpo.WSUSserverAlternateSSLProtocol != null)
                    {
                        cache.Add(gpo.WSUSserverAlternate);
                        foreach (var protocol in gpo.WSUSserverAlternateSSLProtocol)
                        {
                            switch (protocol)
                            {
                                case "Ssl2":
                                case "Ssl3":
                                    AddRawDetail(gpo.WSUSserverAlternate, protocol);
                                    break;
                            }
                        }
                    }
                }
            }
            return null;
        }
    }
}
