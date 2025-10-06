//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;
using System;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-LAPS-Not-Installed", RiskRuleCategory.Anomalies, RiskModelCategory.PassTheCredential)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 15)]
    [RuleSTIG("V-36438", "Local administrator accounts on domain systems must not share the same password.")]
    [RuleCERTFR("CERTFR-2015-ACT-046", "SECTION00020000000000000000")]
    [RuleMaturityLevel(3)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.ValidAccountsLocalAccounts)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.PrivilegedAccountManagement)]
    public class HeatlcheckRuleAnomalyLAPS : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            return (healthcheckData.LAPSInstalled == DateTime.MaxValue && healthcheckData.NewLAPSInstalled == DateTime.MaxValue ? 1 : 0);
        }
    }
}
