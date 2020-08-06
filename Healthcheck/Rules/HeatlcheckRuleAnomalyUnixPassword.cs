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
	[RuleModel("A-UnixPwd", RiskRuleCategory.Anomalies, RiskModelCategory.PasswordRetrieval)]
	[RuleComputation(RuleComputationType.TriggerOnPresence, 0)]
    [RuleDurANSSI(3, "reversible_password", "Accounts with passwords stored using reversible encryption")]
    public class HeatlcheckRuleAnomalyUnixPassword : RuleBase<HealthcheckData>
    {
		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.UnixPasswordUsers != null)
            {
                foreach (var u in healthcheckData.UnixPasswordUsers)
                {
                    AddRawDetail(u.Name);
                }
            }
            return healthcheckData.UnixPasswordUsersCount;
        }
    }
}
