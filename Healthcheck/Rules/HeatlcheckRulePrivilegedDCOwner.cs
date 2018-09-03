//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.Security.Principal;
using System.Text;

namespace PingCastle.Healthcheck.Rules
{
	[HeatlcheckRuleModel("P-DCOwner", HealthcheckRiskRuleCategory.PrivilegedAccounts, HealthcheckRiskModelCategory.ACLCheck)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnPresence, 10)]
    public class HeatlcheckRulePrivilegedDCOwner : HeatlcheckRuleBase
    {
		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.DomainControllers != null)
            {
                foreach (var DC in healthcheckData.DomainControllers)
                {
                    SecurityIdentifier sid = new SecurityIdentifier(DC.OwnerSID);
                    if (!sid.IsWellKnown(WellKnownSidType.AccountDomainAdminsSid) && !sid.IsWellKnown(WellKnownSidType.AccountEnterpriseAdminsSid))
                    {
                        AddRawDetail(DC.DistinguishedName, DC.OwnerName);
                    }
                }
            }
            return null;
        }
    }
}
