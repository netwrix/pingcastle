//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-SMB2SignatureNotEnabledOnComputer", RiskRuleCategory.Anomalies, RiskModelCategory.NetworkSniffing)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 3)]
    [RuleCERTFR("CERTFR-2015-ACT-021", "SECTION00010000000000000000")]
    [RuleIntroducedIn(3, 3)]
    [RuleMaturityLevel(3)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.ManintheMiddle)]
    public class HeatlcheckRuleAnomalyAllComputerSMB2SignatureNotEnabled : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.AllComputerSmbData == null)
                return null;

            foreach (var computer in healthcheckData.AllComputerSmbData)
            {
                if (computer.SupportSMB2OrSMB3)
                {
                    if (computer.SMB2SecurityMode != SMBSecurityModeEnum.NotTested)
                    {
                        if ((computer.SMB2SecurityMode & SMBSecurityModeEnum.SmbSigningEnabled) == 0)
                        {
                            AddRawDetail(computer.ComputerName);
                        }
                    }
                }
            }
            return null;
        }
    }
}
