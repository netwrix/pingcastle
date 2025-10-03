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
    [RuleModel("ADConnectVersion", RiskRuleCategory.Trusts, RiskModelCategory.TrustAzure)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 15)]
    [RuleMaturityLevel(1)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.ManintheMiddle)]
    public class ADConnectVersion : RuleBase<HealthCheckCloudData>
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
                        if (v < new Version(1, 6, 11, 3))
                        {
                            AddRawDetail(healthCheckCloudData.ProvisionDirSyncClientVersion);
                        }
                    }
                    else if (v.Major == 2)
                    {
                        if (v < new Version(2, 0, 8, 0))
                        {
                            AddRawDetail(healthCheckCloudData.ProvisionDirSyncClientVersion);
                        }
                    }
                }
            }
            return null;
        }

    }
}
