//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("T-SIDHistoryDangerous", RiskRuleCategory.Trusts, RiskModelCategory.SIDHistory)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 10)]
    [RuleANSSI("R15", "paragraph.3.3.1.5")]
    [RuleIntroducedIn(2, 9)]
    [RuleDurANSSI(2, "sidhistory_dangerous", "Accounts or groups with unexpected SID history")]
    [RuleMitreAttackMitigation(MitreAttackMitigation.ActiveDirectoryConfiguration)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.AccessTokenManipulationSIDHistoryInjection)]
    public class HeatlcheckRuleTrustSIDHistoryDangerous : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.UserAccountData != null && healthcheckData.UserAccountData.ListDomainSidHistory != null
                && healthcheckData.UserAccountData.ListDomainSidHistory.Count > 0)
            {
                foreach (HealthcheckSIDHistoryData data in healthcheckData.UserAccountData.ListDomainSidHistory)
                {
                    if (data.DangerousSID)
                    {
                        AddRawDetail(data.FriendlyName);
                    }
                }
            }
            if (healthcheckData.ComputerAccountData != null && healthcheckData.ComputerAccountData.ListDomainSidHistory != null
                && healthcheckData.ComputerAccountData.ListDomainSidHistory.Count > 0)
            {
                foreach (HealthcheckSIDHistoryData data in healthcheckData.ComputerAccountData.ListDomainSidHistory)
                {
                    if (data.DangerousSID)
                    {
                        AddRawDetail(data.FriendlyName);
                    }
                }
            }
            return null;
        }
    }
}
