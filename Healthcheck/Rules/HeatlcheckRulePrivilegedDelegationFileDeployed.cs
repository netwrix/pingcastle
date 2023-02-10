//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("P-DelegationFileDeployed", RiskRuleCategory.PrivilegedAccounts, RiskModelCategory.ACLCheck)]
    [RuleComputation(RuleComputationType.PerDiscover, 5)]
    [RuleANSSI("R18", "subsubsection.3.3.2")]
    [RuleSTIG("V-2370", "The access control permissions for the directory service site group policy must be configured to use the required access permissions.", STIGFramework.ActiveDirectoryService2003)]
    [RuleIntroducedIn(2, 7)]
    [RuleMaturityLevel(2)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.ActiveDirectoryConfiguration)]
    public class HeatlcheckRulePrivilegedDelegationFileDeployed : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.GPPFileDeployed != null)
            {
                foreach (var file in healthcheckData.GPPFileDeployed)
                {
                    if (file.Delegation != null)
                    {
                        foreach (var delegation in file.Delegation)
                        {
                            AddRawDetail(file.GPOName, file.Type, file.FileName, delegation.Account, delegation.Right);
                        }
                    }
                }
            }
            return null;
        }
    }
}
