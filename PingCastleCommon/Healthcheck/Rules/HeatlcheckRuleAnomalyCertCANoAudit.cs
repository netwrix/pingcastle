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
    /// CA Audit Logging disabled (AuditFilter = 0).
    /// The Windows CA service logs certificate lifecycle events (issuance, revocation,
    /// key archival, start/stop) via the AuditFilter registry DWORD under
    /// HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\{CA Name}.
    /// When AuditFilter is 0 no events are written to the Security event log,
    /// so certificate abuse — including issuance of rogue certs — goes undetected.
    /// Microsoft recommends enabling all audit categories (value 127 / 0x7F).
    /// Reference: CIS AD CS Benchmark; MS best-practice hardening guide for AD CS.
    /// </summary>
    [RuleModel("A-CertCANoAudit", RiskRuleCategory.Anomalies, RiskModelCategory.CertificateTakeOver)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 10)]
    [RuleIntroducedIn(3, 3)]
    [RuleMaturityLevel(2)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.StealorForgeKerberosTickets)]
    public class HeatlcheckRuleAnomalyCertCANoAudit : RuleBase<HealthcheckData>
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
                // AuditFilter == 0 → no auditing; null → registry was not readable
                if (ca.AuditFilter == 0)
                {
                    AddRawDetail(ca.Name, ca.DnsHostName);
                }
            }

            return null;
        }
    }
}
