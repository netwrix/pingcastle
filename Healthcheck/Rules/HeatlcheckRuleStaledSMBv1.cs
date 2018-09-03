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
	[HeatlcheckRuleModel("S-SMB-v1", HealthcheckRiskRuleCategory.StaleObjects, HealthcheckRiskModelCategory.OldAuthenticationProtocols)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnPresence, 1)]
    public class HeatlcheckRuleStaledSMBv1 : HeatlcheckRuleBase
    {
		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
			// smb v1 enabled ?
			if (healthcheckData.DomainControllers != null && healthcheckData.DomainControllers.Count > 0)
			{
				foreach (var DC in healthcheckData.DomainControllers)
				{
					if (DC.SupportSMB1 )
					{
						AddRawDetail(DC.DCName);
					}
				}
			}
            return null;
        }
    }
}
