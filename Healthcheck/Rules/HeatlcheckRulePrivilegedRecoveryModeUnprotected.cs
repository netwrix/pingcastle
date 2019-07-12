//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.Text;
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
	[RuleModel("P-RecoveryModeUnprotected", RiskRuleCategory.PrivilegedAccounts, RiskModelCategory.ACLCheck)]
	[RuleComputation(RuleComputationType.TriggerOnPresence, 15)]
	[RuleSTIG("V-1159", "The Recovery Console option is set to permit automatic logon to the system.", STIGFramework.Windows7)]
	[RuleIntroducedIn(2, 7)]
	public class HeatlcheckRulePrivilegedRecoveryModeUnprotected : RuleBase<HealthcheckData>
    {
		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
			foreach (GPPSecurityPolicy policy in healthcheckData.GPOLsaPolicy)
            {
                foreach (GPPSecurityPolicyProperty property in policy.Properties)
                {
					if (property.Property == "recoveryconsole_securitylevel")
                    {
                        if (property.Value > 0)
                        {
							AddRawDetail(policy.GPOName);
							break;
                        }
                    }
                }
            }
			return null;
        }
    }
}
