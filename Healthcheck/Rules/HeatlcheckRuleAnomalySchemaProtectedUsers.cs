//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-ProtectedUsers", RiskRuleCategory.Anomalies, RiskModelCategory.PassTheCredential)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 0)]
    [RuleSTIG("V-78131", "Accounts with domain level administrative privileges must be members of the Protected Users group in domains with a domain functional level of Windows 2012 R2 or higher.")]
    [RuleCERTFR("CERTFR-2017-ALE-012")]
    [RuleMaturityLevel(3)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.PrivilegedAccountManagement)]
    public class HeatlcheckRuleAnomalySchemaProtectedUsers : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.SchemaVersion < 69)
                return 1;
            return 0;
        }
    }
}
