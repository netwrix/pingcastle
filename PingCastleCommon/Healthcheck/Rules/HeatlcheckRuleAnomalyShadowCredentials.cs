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
    /// Shadow Credentials: accounts with msDS-KeyCredentialLink entries.
    /// The msDS-KeyCredentialLink attribute stores Windows Hello for Business (WHfB) / FIDO2
    /// device credentials tied to an AD account. An attacker who can write to this attribute
    /// (e.g. via GenericWrite / WriteProperty on the account object) can add a forged
    /// key credential and then authenticate as the target using PKINIT — without needing
    /// the account's password. This technique bypasses password-based protections and
    /// survives password resets. Privileged account targets (Domain Admins, DC machine
    /// accounts) allow full domain compromise.
    /// Detection: unexpected entries in msDS-KeyCredentialLink on user or computer objects.
    /// Mitigation: restrict write access to msDS-KeyCredentialLink; monitor attribute changes.
    /// Reference: "Shadow Credentials" – Elad Shamir (SpecterOps), 2022.
    /// </summary>
    [RuleModel("A-ShadowCredentials", RiskRuleCategory.Anomalies, RiskModelCategory.CertificateTakeOver)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 15)]
    [RuleIntroducedIn(3, 3)]
    [RuleMaturityLevel(2)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.StealorForgeKerberosTickets)]
    public class HeatlcheckRuleAnomalyShadowCredentials : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.ShadowCredentials == null
                || healthcheckData.ShadowCredentials.Count == 0)
                return null;

            foreach (var entry in healthcheckData.ShadowCredentials)
            {
                AddRawDetail(
                    entry.AccountName,
                    entry.CredentialCount.ToString(),
                    entry.IsPrivileged ? "Privileged" : "Standard");
            }

            return null;
        }
    }
}
