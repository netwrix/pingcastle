//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-CertEnrollChannelBinding", RiskRuleCategory.Anomalies, RiskModelCategory.CertificateTakeOver)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 5)]
    [RuleIntroducedIn(2, 11)]
    [RuleMaturityLevel(3)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.ManintheMiddle)]
    public class HeatlcheckRuleAnomalyCertEnrollCB : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.CertificateEnrollments != null)
            {
                foreach (var ce in healthcheckData.CertificateEnrollments)
                {
                    if (ce.WebEnrollmentChannelBindingDisabled)
                    {
                        AddRawDetail(ce.Name, "WebEnrollment");
                    }
                    if (ce.CESChannelBindingDisabled)
                    {
                        AddRawDetail(ce.Name, "CES");
                    }
                }
            }
            return null;
        }
    }
}
