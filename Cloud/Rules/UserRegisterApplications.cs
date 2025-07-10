using PingCastle.Rules;
//
// Copyright (c) Vincent LE TOUX for Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Cloud.Data;

namespace PingCastle.Cloud.Rules
{
    [RuleModel("UserRegisterApplications", RiskRuleCategory.StaleObjects, RiskModelCategory.Provisioning)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 5)]
    [RuleMaturityLevel(2)]
    public class UserRegisterApplications : RuleBase<HealthCheckCloudData>
    {
        protected override int? AnalyzeDataNew(HealthCheckCloudData healthCheckCloudData)
        {
            if (healthCheckCloudData.UsersPermissionToCreateLOBAppsEnabled == true)
            {
                AddRawDetail("true");
            }
            return null;
        }

    }
}
