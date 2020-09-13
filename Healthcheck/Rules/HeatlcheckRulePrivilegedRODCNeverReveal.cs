//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//

using System.Collections.Generic;
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("P-RODCNeverReveal", RiskRuleCategory.PrivilegedAccounts, RiskModelCategory.RODC)]
	[RuleComputation(RuleComputationType.TriggerOnPresence, 5)]
    [RuleIntroducedIn(2,9)]
    [RuleDurANSSI(3, "rodc_never_reveal", "Dangerous configuration of read-only domain controllers (RODC) (neverReveal)")]
    public class HeatlcheckRulePrivilegedRODCNeverReveal : RuleBase<HealthcheckData>
    {
		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.DomainFunctionalLevel < 3)
                return 0;

            foreach (var dc in healthcheckData.DomainControllers)
            {
                if (!dc.RODC)
                    continue;
                var mandatoryDN = new Dictionary<string, string>();

                mandatoryDN.Add("S-1-5-32-544", "Administrators");
                mandatoryDN.Add("S-1-5-32-549", "Server Operators");
                mandatoryDN.Add("S-1-5-32-548", "Account Operators");
                mandatoryDN.Add("S-1-5-32-551", "Backup Operators");
                mandatoryDN.Add(healthcheckData.DomainSid + "-572", "Denied RODC Password Replication Group");

                if (dc.msDSNeverRevealGroup != null)
                {
                    foreach (var member in dc.msDSNeverRevealGroup)
                    {
                        if (mandatoryDN.ContainsKey(member))
                            mandatoryDN.Remove(member);
                    }
                }
                foreach (var missing in mandatoryDN.Values)
                {
                    AddRawDetail(dc.DCName, missing);
                }
            }
            return null;
        }
    }
}
