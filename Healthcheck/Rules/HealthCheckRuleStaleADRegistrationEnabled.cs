//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//

using System.Diagnostics;
using PingCastle.Rules;

namespace PingCastle.HealthCheck.Rules
{
	[RuleModel("S-ADRegistration", RiskRuleCategory.StaleObjects, RiskModelCategory.Provisioning)]
	[RuleComputation(RuleComputationType.TriggerOnPresence, 10)]
    [RuleMaturityLevel(3)]
    public class HealthCheckRuleStaleADRegistrationEnabled : RuleBase<HealthCheckData>
    {
		protected override int? AnalyzeDataNew(HealthCheckData healthcheckData)
        {
            if (healthcheckData.MachineAccountQuota > 0)
            {
                foreach(GPPRightAssignment right in healthcheckData.GPPRightAssignment)
                {
                    if (right.Privilege == "SeMachineAccountPrivilege")
                    {
                        if (right.User == "Everyone"
                            || right.User == "Authenticated Users"
							|| right.User == "Users"
							|| right.User == "Anonymous"
							)
                        {
                            Trace.WriteLine("SeMachineAccountPrivilege found in GPO " + right.GPOName);
							return healthcheckData.MachineAccountQuota;
                        }
                    }
                }
            }
            return 0;
        }
    }
}
