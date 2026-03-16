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
    /// ESC10 – Weak Certificate Mappings on Domain Controllers.
    /// When StrongCertificateBindingEnforcement is set to 0 (disabled) or 1 (compatibility mode)
    /// in the KDC registry, weak certificate-to-account mapping is used during PKINIT authentication.
    /// Combined with a compromised certificate (e.g. via ESC6), this allows an attacker to
    /// authenticate as any domain user including administrators without a valid SID binding.
    /// Registry: HKLM\SYSTEM\CurrentControlSet\Services\Kdc\StrongCertificateBindingEnforcement
    /// Reference: Certified Pre-Owned – ESC10 (SpecterOps).
    /// </summary>
    [RuleModel("A-CertStrongBinding", RiskRuleCategory.Anomalies, RiskModelCategory.CertificateTakeOver)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 10)]
    [RuleIntroducedIn(3, 3)]
    [RuleMaturityLevel(2)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.StealorForgeKerberosTickets)]
    public class HeatlcheckRuleAnomalyCertStrongBinding : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.DomainControllers == null)
                return null;

            foreach (var dc in healthcheckData.DomainControllers)
            {
                if (dc.StrongCertificateBindingEnforcement == null)
                    continue;

                // 0 = disabled (most vulnerable), 1 = compatibility mode (partially vulnerable)
                // 2 = full enforcement (secure) — do not flag
                if (dc.StrongCertificateBindingEnforcement < 2)
                {
                    var level = dc.StrongCertificateBindingEnforcement == 0 ? "Disabled" : "Compatibility mode";
                    AddRawDetail(dc.DCName, level);
                }
            }

            return null;
        }
    }
}
