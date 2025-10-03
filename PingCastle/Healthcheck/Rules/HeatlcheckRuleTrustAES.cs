//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("T-AlgsAES", RiskRuleCategory.Trusts, RiskModelCategory.OldTrustProtocol)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 1)]
    [RuleMaturityLevel(4)]
    [RuleIntroducedIn(2, 11)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.ActiveDirectoryConfiguration)]
    public class HeatlcheckRuleTrustAES : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            // trust
            foreach (HealthCheckTrustData trust in healthcheckData.Trusts)
            {
                if (trust.TrustDirection == 2)
                {
                    continue;
                }
                if (trust.msDSSupportedEncryptionTypes == 0)
                {
                    AddRawDetail(trust.TrustPartner, "Not Configured");
                }
                else if ((trust.msDSSupportedEncryptionTypes & (8 + 16)) == 0)
                {
                    AddRawDetail(trust.TrustPartner, "AES not enabled");
                }
            }
            return null;
        }
    }
}
