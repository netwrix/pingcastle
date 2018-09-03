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
	[HeatlcheckRuleModel("P-ServiceDomainAdmin", HealthcheckRiskRuleCategory.PrivilegedAccounts, HealthcheckRiskModelCategory.PrivilegeControl)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnThreshold, 15, Threshold: 2)]
    [HeatlcheckRuleSTIG("V-36432")]
    public class HeatlcheckRulePrivilegedServiceDomainAdmin : HeatlcheckRuleBase
    {
		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            HealthCheckGroupData domainadmins = null;
            foreach (HealthCheckGroupData group in healthcheckData.PrivilegedGroups)
            {
                if (group.GroupName == "Domain Admins")
                {
                    domainadmins = group;
                    break;
                }
            }
            if (domainadmins == null)
            {
                Trace.WriteLine("Group domain admins not found");
				return 0;
            }
            if (domainadmins.Members != null)
            {
                return domainadmins.NumberOfMemberPwdNeverExpires;
            }
            int countnok = 0;
            int countexception = 0;
            foreach (var member in domainadmins.Members)
            {
                if (member.DoesPwdNeverExpires)
                {
                    if (member.PwdLastSet > DateTime.Now.AddDays(-30))
                    {
                        Trace.WriteLine("Rule for pwd last set disable because password changed recently for " + member.Name);
                        countexception++;
                    }
                    else
                    {
                        countnok++;
                    }
                }
            }
            return countnok;
        }
    }
}
