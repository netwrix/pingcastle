//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("T-Downlevel", RiskRuleCategory.Trusts, RiskModelCategory.OldTrustProtocol)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 20)]
    [RuleMaturityLevel(3)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.PrivilegedAccountManagement)]
    public class HeatlcheckRuleTrustDownlevel : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
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
