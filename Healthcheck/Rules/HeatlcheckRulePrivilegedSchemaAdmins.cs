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
	[HeatlcheckRuleModel("P-SchemaAdmin", HealthcheckRiskRuleCategory.PrivilegedAccounts, HealthcheckRiskModelCategory.IrreversibleChange)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnPresence, 10)]
    [HeatlcheckRuleSTIG("V-72835", true)]
    public class HeatlcheckRulePrivilegedSchemaAdmins : HeatlcheckRuleBase
    {
		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            foreach (HealthCheckGroupData group in healthcheckData.PrivilegedGroups)
            {
                if (group.GroupName == "Schema Admins")
                {
                    if (group.NumberOfMember > 0)
                    {
						return group.NumberOfMember;
                    }
                }
            }
            return 0;
        }
    }
}
