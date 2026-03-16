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
    /// ESC14 – Weak Explicit Certificate Mapping (altSecurityIdentities).
    /// AD accounts can have explicit certificate-to-account mappings defined via the
    /// altSecurityIdentities attribute. Weak mapping types (RFC822/email, UPN,
    /// Subject-only) rely on certificate fields that an attacker can influence:
    ///   • RFC822: attacker sets the victim's mail attribute to match and enrolls a cert.
    ///   • UPN:    attacker sets the victim's userPrincipalName to match.
    ///   • SubjectOnly: DN-based without issuer — predictable and reusable across CAs.
    /// An attacker who obtains or crafts a certificate matching the weak mapping
    /// can authenticate as the mapped account. The risk is highest for privileged accounts.
    /// Reference: Certified Pre-Owned – ESC14 (SpecterOps).
    /// </summary>
    [RuleModel("A-CertESC14WeakAltSecMapping", RiskRuleCategory.Anomalies, RiskModelCategory.CertificateTakeOver)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 15)]
    [RuleIntroducedIn(3, 3)]
    [RuleMaturityLevel(2)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.StealorForgeKerberosTickets)]
    public class HeatlcheckRuleAnomalyCertESC14WeakAltSecMapping : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.WeakAltSecurityIdentities == null
                || healthcheckData.WeakAltSecurityIdentities.Count == 0)
                return null;

            foreach (var entry in healthcheckData.WeakAltSecurityIdentities)
            {
                AddRawDetail(
                    entry.AccountName,
                    entry.MappingType,
                    entry.IsPrivileged ? "Privileged" : "Standard",
                    entry.MappingValue);
            }

            return null;
        }
    }
}
