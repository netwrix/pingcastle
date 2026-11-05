//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-CertTempCustomSubject", RiskRuleCategory.Anomalies, RiskModelCategory.CertificateTakeOver)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 15)]
    [RuleIntroducedIn(2, 9, 3)]
    [RuleDurANSSI(1, "adcs_template_auth_enroll_with_name", "Dangerous enrollment permission on authentication certificate templates")]
    [RuleMitreAttackTechnique(MitreAttackTechnique.StealorForgeKerberosTickets)]
    public class HeatlcheckRuleAnomalyCertTempCustomSubject : HeatlcheckRuleAnomalyCertTempBase
    {
        protected override bool IsVulnerable(HealthCheckCertificateTemplate ct)
        {
            return !ct.CAManagerApproval && ct.IssuanceRequirementsEmpty && ct.LowPrivCanEnroll && ct.HasAuthenticationEku
                            && ct.EnrolleeSupplies > 0 && ct.EnrollmentLowPrivilegePrincipals.Count > 0;
        }
    }
}
