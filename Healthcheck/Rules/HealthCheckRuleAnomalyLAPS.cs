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
    [RuleModel("A-LAPS-Not-Installed", RiskRuleCategory.Anomalies, RiskModelCategory.PassTheCredential)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 15)]
    [RuleSTIG("V-36438", "Local administrator accounts on domain systems must not share the same password.")]
    [RuleCERTFR("CERTFR-2015-ACT-046", "SECTION00020000000000000000")]
    [RuleMaturityLevel(3)]
    public class HealthCheckRuleAnomalyLAPS : RuleBase<HealthCheckData>
    {
        protected override int? AnalyzeDataNew(HealthCheckData healthcheckData)
        {
            return (healthcheckData.LAPSInstalled == DateTime.MaxValue ? 1 : 0);
        }
    }
}