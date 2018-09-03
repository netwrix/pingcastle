//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.Text;

namespace PingCastle.Healthcheck.Rules
{
	[HeatlcheckRuleModel("S-OS-2000", HealthcheckRiskRuleCategory.StaleObjects, HealthcheckRiskModelCategory.ObsoleteOS)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnPresence, 40)]
    public class HeatlcheckRuleStaledObsolete2000 : HeatlcheckRuleBase
    {
		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            foreach (HealthcheckOSData os in healthcheckData.OperatingSystem)
            {
                if (os.OperatingSystem == "Windows 2000")
                {
                    return os.NumberOfOccurence;
                }
            }
            return 0;
        }
    }
}
