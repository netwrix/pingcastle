//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;
using System;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("P-RODCRevealOnDemand", RiskRuleCategory.PrivilegedAccounts, RiskModelCategory.RODC)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 5)]
    [RuleIntroducedIn(2, 9)]
    [RuleDurANSSI(3, "rodc_reveal", "Dangerous configuration of read-only domain controllers (RODC) (reveal)")]
    [RuleMitreAttackMitigation(MitreAttackMitigation.ActiveDirectoryConfiguration)]
    public class HeatlcheckRulePrivilegedRODCRevealOnDemand : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.DomainFunctionalLevel < 3)
                return 0;

            foreach (var dc in healthcheckData.DomainControllers)
            {
                if (string.Equals(dc.DCName, "AzureADKerberos", StringComparison.OrdinalIgnoreCase))
                {
                    // Ugly Entra ID Kerberos stuff
                    // https://techcommunity.microsoft.com/t5/azure-active-directory-identity/public-preview-of-azure-ad-support-for-fido2-security-keys-in/ba-p/1187929
                    continue;
                }
                if (dc.msDSRevealOnDemandGroup != null)
                {
                    foreach (var account in dc.msDSRevealOnDemandGroup)
                    {
                        var sidpart = account.Split('-');
                        var rid = int.Parse(sidpart[sidpart.Length - 1]);
                        if (rid < 1000 && rid != 571) // 571 is allowed RODC Password
                        {
                            AddRawDetail(dc.DCName, account);
                        }
                    }
                }
            }
            return null;
        }
    }
}
