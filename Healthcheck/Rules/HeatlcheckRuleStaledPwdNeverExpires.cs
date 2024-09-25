//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("S-PwdNeverExpires", RiskRuleCategory.StaleObjects, RiskModelCategory.ObjectConfig)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 1)]
    [RuleIntroducedIn(2, 9)]
    [RuleDurANSSI(2, "dont_expire", "Accounts with never-expiring passwords")]
    [RuleMitreAttackMitigation(MitreAttackMitigation.ActiveDirectoryConfiguration)]
    public class HeatlcheckRuleStaledPwdNeverExpires : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.UserAccountData.ListPwdNeverExpires != null)
            {
                if (healthcheckData.UserAccountData.NumberPwdNeverExpires < maxNumDisplayAccount)
                {
                    for (int i = 0; i < healthcheckData.UserAccountData.NumberPwdNeverExpires; i++)
                    {
                        AddRawDetail(healthcheckData.UserAccountData.ListPwdNeverExpires[i].DistinguishedName);
                    }
                    return null;
                }
            }
            return healthcheckData.UserAccountData.NumberPwdNeverExpires;
        }
    }
}
