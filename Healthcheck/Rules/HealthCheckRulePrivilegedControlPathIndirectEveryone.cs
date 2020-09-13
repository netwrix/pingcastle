//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//

using PingCastle.Rules;

namespace PingCastle.HealthCheck.Rules
{
    [RuleModel("P-ControlPathIndirectEveryone", RiskRuleCategory.PrivilegedAccounts, RiskModelCategory.ControlPath)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 25)]
    [RuleIntroducedIn(2, 8)]
    [RuleMaturityLevel(1)]
    public class HealthCheckRulePrivilegedControlPathIndirectEveryone : RuleBase<HealthCheckData>
    {
        protected override int? AnalyzeDataNew(HealthCheckData healthcheckData)
        {
            if (healthcheckData.ControlPaths == null)
                return 0;
            foreach (var analysis in healthcheckData.ControlPaths.Data)
            {
                if (analysis.Typology == Data.CompromiseGraphDataTypology.Infrastructure
                    || analysis.Typology == Data.CompromiseGraphDataTypology.PrivilegedAccount)
                {
				    if (analysis.CriticalObjectFound)
                    {
                        AddRawDetail(analysis.Description);
                    }
                }
            }
            return null;
        }
    }
}
