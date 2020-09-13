﻿//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//

using System;
using PingCastle.Rules;

namespace PingCastle.HealthCheck.Rules
{
    [RuleModel("T-AzureADSSO", RiskRuleCategory.Trusts, RiskModelCategory.TrustAzure)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 20)]
    [RuleDurANSSI(2, "trusts_accounts", "Trust account passwords unchanged for more than a year")]
    public class HealthCheckRuleTrustAzureADSSO : RuleBase<HealthCheckData>
    {
        protected override int? AnalyzeDataNew(HealthCheckData healthcheckData)
        {
            if (healthcheckData.AzureADSSOLastPwdChange != DateTime.MinValue && healthcheckData.AzureADSSOLastPwdChange.AddYears(1) < DateTime.Now)
            {
                return 1;
            }
            return null;
        }
    }
}