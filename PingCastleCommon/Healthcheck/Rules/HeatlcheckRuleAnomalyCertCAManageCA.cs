//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    /// <summary>
    /// ESC7 – Vulnerable CA Access Control.
    /// A low-privileged principal holds the ManageCA right on a Certificate Authority,
    /// enabling them to change CA settings (e.g. enable EDITF_ATTRIBUTESUBJECTALTNAME2)
    /// or approve pending certificate requests, which can lead to domain compromise.
    /// Reference: Certified Pre-Owned – ESC7 (SpecterOps).
    /// </summary>
    [RuleModel("A-CertCAManageCA", RiskRuleCategory.Anomalies, RiskModelCategory.CertificateTakeOver)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 15)]
    [RuleIntroducedIn(3, 3)]
    [RuleMaturityLevel(2)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.StealorForgeKerberosTickets)]
    public class HeatlcheckRuleAnomalyCertCAManageCA : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.CertificateAuthorities == null)
                return null;

            foreach (var ca in healthcheckData.CertificateAuthorities)
            {
                if (ca.LowPrivelegedManagerPrincipals != null && ca.LowPrivelegedManagerPrincipals.Count > 0)
                {
                    foreach (var principal in ca.LowPrivelegedManagerPrincipals)
                    {
                        AddRawDetail(ca.Name, ca.DnsHostName, principal);
                    }
                }
            }

            return null;
        }
    }
}
