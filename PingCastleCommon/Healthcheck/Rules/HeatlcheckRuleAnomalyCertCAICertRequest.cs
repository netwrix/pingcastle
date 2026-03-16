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
    /// ESC11 – NTLM Relay to ICertRequest (DCOM/RPC endpoint).
    /// When the IF_ENFORCEENCRYPTICERTREQUEST flag (0x200) is NOT set in a CA's
    /// InterfaceFlags registry value, the ICertRequest DCOM interface accepts
    /// certificate requests without enforcing packet privacy (encryption/signing).
    /// This allows an NTLM relay attack (e.g. via PetitPotam / CVE-2021-36942)
    /// to the CA's RPC endpoint and the issuance of certificates on behalf of
    /// a relayed identity — potentially leading to domain compromise.
    /// Reference: Certified Pre-Owned – ESC11 (SpecterOps / Sylvain Heiniger).
    /// </summary>
    [RuleModel("A-CertCAICertRequest", RiskRuleCategory.Anomalies, RiskModelCategory.CertificateTakeOver)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 10)]
    [RuleIntroducedIn(3, 3)]
    [RuleMaturityLevel(2)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.ManintheMiddle)]
    public class HeatlcheckRuleAnomalyCertCAICertRequest : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.CertificateAuthorities == null)
                return null;

            if (!healthcheckData.IsPrivilegedMode)
            {
                Notice = @"<strong>Reduced confidence</strong><br>Use privilege mode for accuracy";
                NoticeTooltip = "This check requires <b>Privilege mode</b> to read CA registry. Run PingCastle with <code>--privileged</code> for accurate results.";
            }

            foreach (var ca in healthcheckData.CertificateAuthorities)
            {
                // HasEnforceEncryptICertRequest == false means the flag is missing → vulnerable
                // null means the registry key was not readable
                if (ca.HasEnforceEncryptICertRequest == false)
                {
                    AddRawDetail(ca.Name, ca.DnsHostName);
                }
            }

            return null;
        }
    }
}
