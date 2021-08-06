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
    [RuleModel("S-DCRegistration", RiskRuleCategory.StaleObjects, RiskModelCategory.Provisioning)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 10)]
    [RuleIntroducedIn(2, 9)]
    [RuleDurANSSI(1, "dc_inconsistent_uac", "Domain controllers in inconsistent state")]
    [RuleMitreAttackTechnique(MitreAttackTechnique.RogueDomainController)]
    public class HeatlcheckRuleStaleDCRegistrationEnabled : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            foreach (var dc in healthcheckData.DomainControllers)
            {
                if (!string.IsNullOrEmpty(dc.RegistrationProblem))
                {
                    bool isException = false;
                    if (string.Equals(dc.DCName, "AzureADKerberos", StringComparison.OrdinalIgnoreCase))
                    {
                        // Ugly AzureAD Kerberos stuff
                        // https://techcommunity.microsoft.com/t5/azure-active-directory-identity/public-preview-of-azure-ad-support-for-fido2-security-keys-in/ba-p/1187929
                        continue;
                    }
                    if (InfrastructureSettings != null && InfrastructureSettings.Riverbeds != null)
                    {
                        foreach (var riverbed in InfrastructureSettings.Riverbeds)
                        {
                            var test = riverbed.samAccountName;
                            if (test.EndsWith("$"))
                                test = test.Substring(0, test.Length - 1);
                            if (string.Equals(test, dc.DCName, StringComparison.OrdinalIgnoreCase))
                            {
                                isException = true;
                                break;
                            }
                        }
                    }
                    if (!isException)
                    {
                        AddRawDetail(dc.DCName, dc.RegistrationProblem);
                    }
                }
            }
            return null;
        }
    }
}
