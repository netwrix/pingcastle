//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;
using System;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("S-AesNotEnabled", RiskRuleCategory.StaleObjects, RiskModelCategory.OldAuthenticationProtocols)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 0)]
    [RuleDurANSSI(3, "kerberos_properties_encryption", "Service accounts supported encryption algorithms")]
    [RuleMitreAttackTechnique(MitreAttackTechnique.StealorForgeKerberosTicketsASREPRoasting)]
    [RuleIntroducedIn(3, 3)]
    public class HeatlcheckRuleStaledAesNotEnabled : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            // ignore for older OS
            if (healthcheckData.DCWin2008Install == default(DateTime))
                return 0;

            return healthcheckData.UserAccountData.NumberNotAesEnabled + healthcheckData.ComputerAccountData.NumberNotAesEnabled;
        }
    }
}
