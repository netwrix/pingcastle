//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-CertEnrollHttp", RiskRuleCategory.Anomalies, RiskModelCategory.CertificateTakeOver)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 5)]
    [RuleIntroducedIn(2, 11)]
    [RuleMaturityLevel(3)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.ManintheMiddle)]
    public class HeatlcheckRuleAnomalyCertEnrollHttp : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.CertificateEnrollments != null)
            {
                foreach (var ce in healthcheckData.CertificateEnrollments)
                {
                    if (ce.CESHttp)
                    {
                        AddRawDetail(ce.Name, "CES");
                    }
                    if (ce.WebEnrollmentHttp)
                    {
                        AddRawDetail(ce.Name, "WebEnrollment");
                    }
                }
            }
            return null;
        }
    }
}
