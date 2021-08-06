//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("P-RODCSYSVOLWrite", RiskRuleCategory.PrivilegedAccounts, RiskModelCategory.RODC)]
    [RuleComputation(RuleComputationType.PerDiscover, 5)]
    [RuleIntroducedIn(2, 9)]
    [RuleMaturityLevel(2)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.RogueDomainController)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.ActiveDirectoryConfiguration)]
    public class HeatlcheckRulePrivilegedRODCSYSVOLWrite : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.DomainFunctionalLevel < 3)
                return 0;

            foreach (var dc in healthcheckData.DomainControllers)
            {
                if (!dc.RODC)
                    continue;
                if (dc.SYSVOLOverwrite)
                {
                    AddRawDetail(dc.DCName);
                }
            }
            return null;
        }
    }
}
