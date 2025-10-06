//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-SMB2SignatureNotRequired", RiskRuleCategory.Anomalies, RiskModelCategory.NetworkSniffing)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 0)]
    //[RuleBSI("M 2.412")]
    [RuleCERTFR("CERTFR-2015-ACT-021", "SECTION00010000000000000000")]
    [RuleIntroducedIn(2, 5)]
    [RuleMaturityLevel(3)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.ManintheMiddle)]
    public class HeatlcheckRuleAnomalySMB2SignatureNotRequired : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            foreach (var DC in healthcheckData.DomainControllers)
            {
                if (DC.SupportSMB2OrSMB3)
                {
                    if (DC.SMB2SecurityMode != SMBSecurityModeEnum.NotTested)
                    {
                        if ((DC.SMB2SecurityMode & SMBSecurityModeEnum.SmbSigningRequired) == 0)
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
