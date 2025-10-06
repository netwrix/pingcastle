//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-SmartCardPwdRotation", RiskRuleCategory.Anomalies, RiskModelCategory.PassTheCredential)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 0)]
    [RuleSTIG("V-72821", "All accounts, privileged and unprivileged, that require smart cards must have the underlying NT hash rotated at least every 60 days.")]
    [RuleANSSI("R38", "paragraph.3.6.2.2")]
    [RuleDurANSSI(4, "smartcard_expire_passwords", "Missing password expiration for smart card users")]
    [RuleMitreAttackTechnique(MitreAttackTechnique.BruteForcePasswordCracking)]
    [RuleIntroducedIn(3,3)]
    public class HeatlcheckRuleAnomalySmartCardExpirePassword : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.DomainFunctionalLevel >= 7 && !healthcheckData.ExpirePasswordsOnSmartCardOnlyAccounts)
                return 1;
            return 0;
        }
    }
}
