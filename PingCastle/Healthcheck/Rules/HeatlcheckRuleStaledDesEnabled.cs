//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("S-DesEnabled", RiskRuleCategory.StaleObjects, RiskModelCategory.OldAuthenticationProtocols)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 15)]
    [RuleDurANSSI(2, "kerberos_properties_deskey", "Use of Kerberos with weak encryption")]
    [RuleMitreAttackTechnique(MitreAttackTechnique.StealorForgeKerberosTicketsASREPRoasting)]
    public class HeatlcheckRuleStaledDesEnabled : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.UserAccountData.ListDesEnabled != null || healthcheckData.ComputerAccountData.ListDesEnabled != null)
            {
                if (healthcheckData.UserAccountData.ListDesEnabled != null)
                {
                    if (healthcheckData.UserAccountData.NumberDesEnabled < maxNumDisplayAccount)
                    {
                        for (int i = 0; i < healthcheckData.UserAccountData.NumberDesEnabled; i++)
                        {
                            AddRawDetail(healthcheckData.UserAccountData.ListDesEnabled[i].DistinguishedName);
                        }
                    }
                }
                if (healthcheckData.ComputerAccountData.ListDesEnabled != null)
                {
                    if (healthcheckData.ComputerAccountData.NumberDesEnabled < maxNumDisplayAccount)
                    {
                        for (int i = 0; i < healthcheckData.ComputerAccountData.NumberDesEnabled; i++)
                        {
                            AddRawDetail(healthcheckData.ComputerAccountData.ListDesEnabled[i].DistinguishedName);
                        }
                    }
                }
            }

            if (healthcheckData.UserAccountData.NumberDesEnabled + healthcheckData.ComputerAccountData.NumberDesEnabled < maxNumDisplayAccount)
                return null;
            return healthcheckData.UserAccountData.NumberDesEnabled + healthcheckData.ComputerAccountData.NumberDesEnabled;
        }
    }
}
