//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("S-C-Reversible", RiskRuleCategory.StaleObjects, RiskModelCategory.ObjectConfig)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 5)]
    [RuleDurANSSI(3, "reversible_password", "Accounts with passwords stored using reversible encryption")]
    [RuleMitreAttackTechnique(MitreAttackTechnique.BruteForcePasswordCracking)]
    public class HeatlcheckRuleStaledReversibleEncryptionComputer : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            return healthcheckData.ComputerAccountData.NumberReversibleEncryption;
        }
    }
}
