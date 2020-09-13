//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//

using PingCastle.Rules;

namespace PingCastle.HealthCheck.Rules
{
    [RuleModel("A-SMB2SignatureNotEnabled", RiskRuleCategory.Anomalies, RiskModelCategory.NetworkSniffing)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 5)]

    //[RuleBSI("M 2.412")]
    [RuleCERTFR("CERTFR-2015-ACT-021", "SECTION00010000000000000000")]
    [RuleIntroducedIn(2, 5)]
    [RuleMaturityLevel(3)]
    public class HealthCheckRuleAnomalySMB2SignatureNotEnabled : RuleBase<HealthCheckData>
    {
        protected override int? AnalyzeDataNew(HealthCheckData healthcheckData)
        {
            foreach (var DC in healthcheckData.DomainControllers)
            {
                if (DC.SupportSMB2OrSMB3)
                {
                    if (DC.SMB2SecurityMode != SMBSecurityModeEnum.NotTested)
                    {
                        if ((DC.SMB2SecurityMode & SMBSecurityModeEnum.SmbSigningEnabled) == 0)
                        {
                            AddRawDetail(DC.DCName);
                        }
                    }
                }
            }
            return null;
        }
    }
}