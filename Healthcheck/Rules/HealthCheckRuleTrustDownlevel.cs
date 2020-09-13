//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//

using PingCastle.Rules;

namespace PingCastle.HealthCheck.Rules
{
    [RuleModel("T-Downlevel", RiskRuleCategory.Trusts, RiskModelCategory.OldTrustProtocol)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 20)]
    [RuleMaturityLevel(3)]
    public class HealthCheckRuleTrustDownlevel : RuleBase<HealthCheckData>
    {
        protected override int? AnalyzeDataNew(HealthCheckData healthcheckData)
        {
            // trust
            foreach (HealthCheckTrustData trust in healthcheckData.Trusts)
            {
                if (trust.TrustType == 1)
                {
                    AddRawDetail(trust.TrustPartner);
                }
            }
            return null;
        }
    }
}