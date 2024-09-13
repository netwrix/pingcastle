﻿using PingCastle.Rules;
//
// Copyright (c) Vincent LE TOUX for Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Cloud.Data;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PingCastle.Cloud.Rules
{
    [RuleModel("UserConsentCompanyData", RiskRuleCategory.Anomalies, RiskModelCategory.Reconnaissance)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 5)]
    [RuleMaturityLevel(2)]
    public class UserConsentCompanyData : RuleBase<HealthCheckCloudData>
    {
        protected override int? AnalyzeDataNew(HealthCheckCloudData healthCheckCloudData)
        {
            // disable the rule since MS changed the rule logic
            /*
            if (healthCheckCloudData.UsersPermissionToUserConsentToAppEnabled == true)
            {
                AddRawDetail("true");
            }*/
            return null;
        }

    }
}
