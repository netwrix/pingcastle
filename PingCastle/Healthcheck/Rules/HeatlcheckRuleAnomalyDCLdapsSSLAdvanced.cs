//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-DCLdapsProtocolAdvanced", RiskRuleCategory.Anomalies, RiskModelCategory.CertificateTakeOver)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 0)]
    [RuleIntroducedIn(3, 1)]
    [RuleMaturityLevel(5)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.WeakenEncryptionReduceKeySpace)]
    public class HeatlcheckRuleAnomalyDCLdapsSSLAdvanced : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            foreach (var dc in healthcheckData.DomainControllers)
            {
                if (dc.LDAPSProtocols == null)
                    continue;
                foreach (var protocol in dc.LDAPSProtocols)
                {
                    switch (protocol)
                    {
                        case "Tls":
                        case "Tls11":
                            AddRawDetail(dc.DCName, protocol);
                            break;
                    }
                }
            }
            return null;
        }
    }
}
