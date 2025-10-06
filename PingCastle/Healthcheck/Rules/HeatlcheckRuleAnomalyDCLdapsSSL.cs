//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-DCLdapsProtocol", RiskRuleCategory.Anomalies, RiskModelCategory.CertificateTakeOver)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 10)]
    [RuleIntroducedIn(2, 8)]
    [RuleMaturityLevel(3)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.WeakenEncryptionReduceKeySpace)]
    public class HeatlcheckRuleAnomalyDCLdapsSSL : RuleBase<HealthcheckData>
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
                        case "Ssl2":
                        case "Ssl3":
                            AddRawDetail(dc.DCName, protocol);
                            break;
                    }
                }
            }
            return null;
        }
    }
}
