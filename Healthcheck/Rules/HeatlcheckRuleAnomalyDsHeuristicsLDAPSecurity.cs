//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-DsHeuristicsLDAPSecurity", RiskRuleCategory.Anomalies, RiskModelCategory.Reconnaissance)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 0)]
    [RuleDurANSSI(3, "dsheuristics_bad", "Dangerous dsHeuristics settings")]
    [RuleIntroducedIn(2, 10, 1)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.ForcedAuthentication)]
    public class HeatlcheckRuleAnomalyDsHeuristicsLDAPSecurity : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (string.IsNullOrEmpty(healthcheckData.DSHeuristics) || healthcheckData.DSHeuristics.Length < 28)
            {
                AddRawDetail("LDAPAddAuthZVerifications", "28th", "Not Set");
            }
            else
            {
                var v = healthcheckData.DSHeuristics.Substring(27, 1);
                if (v != "1")
                {
                    AddRawDetail("LDAPAddAuthZVerifications", "28th", v);
                }
            }
            if (string.IsNullOrEmpty(healthcheckData.DSHeuristics) || healthcheckData.DSHeuristics.Length < 29)
            {
                AddRawDetail("LDAPOwnerModify", "29th", "Not Set");
            }
            else
            {
                var v = healthcheckData.DSHeuristics.Substring(28, 1);
                if (v != "1")
                {
                    AddRawDetail("LDAPOwnerModify", "29th", v);
                }
            }
            return null;
        }
    }
}
