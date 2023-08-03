//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("P-AdminEmailOn", RiskRuleCategory.PrivilegedAccounts, RiskModelCategory.ControlPath)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 0)]
    [RuleMaturityLevel(3)]
    [RuleIntroducedIn(3, 1)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.PrivilegedAccountManagement)]
    public class HeatlcheckRulePrivilegedEmailOn : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            foreach (var member in healthcheckData.AllPrivilegedMembers)
            {
                if (member.IsEnabled && !string.IsNullOrEmpty(member.Email))
                {
                    AddRawDetail(member.Name, member.Email);
                }
            }
            return null;
        }
    }
}
