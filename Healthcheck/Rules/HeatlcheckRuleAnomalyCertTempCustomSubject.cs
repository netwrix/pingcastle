//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;
using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-CertTempCustomSubject", RiskRuleCategory.Anomalies, RiskModelCategory.CertificateTakeOver)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 15)]
    [RuleIntroducedIn(2, 9, 3)]
    [RuleMaturityLevel(2)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.StealorForgeKerberosTickets)]
    public class HeatlcheckRuleAnomalyCertTempCustomSubject : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.CertificateTemplates != null)
            {
                foreach (var ct in healthcheckData.CertificateTemplates)
                {
                    if (!ct.CAManagerApproval && ct.IssuanceRequirementsEmpty && ct.LowPrivCanEnroll && ct.HasAuthenticationEku && ct.EnrolleeSupplies > 0)
                    {
                        AddRawDetail(ct.Name);
                    }
                }
            }
            return null;
        }
    }
}
