//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("S-PrimaryGroup", RiskRuleCategory.StaleObjects, RiskModelCategory.ObjectConfig)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 15)]
    [RuleDurANSSI(3, "primary_group_id_nochange", "Accounts with modified PrimaryGroupID")]
    [RuleMitreAttackMitigation(MitreAttackMitigation.ActiveDirectoryConfiguration)]
    public class HeatlcheckRuleStaledPrimaryGroup : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.UserAccountData.ListBadPrimaryGroup != null)
            {
                if (healthcheckData.UserAccountData.NumberBadPrimaryGroup < maxNumDisplayAccount)
                {
                    for (int i = 0; i < healthcheckData.UserAccountData.NumberBadPrimaryGroup; i++)
                    {
                        AddRawDetail(healthcheckData.UserAccountData.ListBadPrimaryGroup[i].DistinguishedName);
                    }
                    return null;
                }
            }
            return healthcheckData.UserAccountData.NumberBadPrimaryGroup;
        }
    }
}
