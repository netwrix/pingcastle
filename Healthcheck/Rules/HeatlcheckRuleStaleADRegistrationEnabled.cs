//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace PingCastle.Healthcheck.Rules
{
	[HeatlcheckRuleModel("S-ADRegistration", HealthcheckRiskRuleCategory.StaleObjects, HealthcheckRiskModelCategory.Provisioning)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnPresence, 10)]
    public class HeatlcheckRuleStaleADRegistrationEnabled : HeatlcheckRuleBase
    {
		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.MachineAccountQuota > 0)
            {
                foreach(GPPRightAssignment right in healthcheckData.GPPRightAssignment)
                {
                    if (right.Privilege == "SeMachineAccountPrivilege")
                    {
                        if (right.User == "Everyone"
                            || right.User == "Authenticated Users")
                        {
                            Trace.WriteLine("SeMachineAccountPrivilege found in GPO " + right.GPOName);
                            return 1;
                        }
                    }
                }
            }
            return 0;
        }
    }
}
