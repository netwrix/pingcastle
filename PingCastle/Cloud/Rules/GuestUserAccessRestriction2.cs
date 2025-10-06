using PingCastle.Rules;
//
// Copyright (c) Vincent LE TOUX for Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Cloud.Data;
using System;

namespace PingCastle.Cloud.Rules
{
    [RuleModel("GuestUserAccessRestriction2", RiskRuleCategory.Anomalies, RiskModelCategory.WeakPassword)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 0)]
    [RuleMaturityLevel(4)]
    public class GuestUserAccessRestriction2 : RuleBase<HealthCheckCloudData>
    {
        protected override int? AnalyzeDataNew(HealthCheckCloudData healthCheckCloudData)
        {
            if (string.Equals(healthCheckCloudData.PolicyGuestUserRoleId, "10dae51f-b6af-4016-8d66-8c2a99b929b3", StringComparison.OrdinalIgnoreCase))
            {
                AddRawDetail(healthCheckCloudData.PolicyGuestUserRoleId);
            }
            return null;
        }

    }
}
