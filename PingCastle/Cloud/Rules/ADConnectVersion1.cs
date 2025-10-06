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
    [RuleModel("ADConnectVersion1", RiskRuleCategory.Trusts, RiskModelCategory.TrustAzure)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 5)]
    [RuleMaturityLevel(2)]
    public class ADConnectVersion1 : RuleBase<HealthCheckCloudData>
    {
        protected override int? AnalyzeDataNew(HealthCheckCloudData healthCheckCloudData)
        {
            if (healthCheckCloudData.ProvisionDirectorySynchronizationStatus == "Enabled")
            {
                Version v;
                if (Version.TryParse(healthCheckCloudData.ProvisionDirSyncClientVersion, out v))
                {
                    if (v.Major == 1)
                    {
                        AddRawDetail(healthCheckCloudData.ProvisionDirSyncClientVersion);
                    }
                }
            }
            return null;
        }

    }
}
