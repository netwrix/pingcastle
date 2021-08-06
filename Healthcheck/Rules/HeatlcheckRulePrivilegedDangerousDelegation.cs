//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("P-DangerousExtendedRight", RiskRuleCategory.PrivilegedAccounts, RiskModelCategory.ACLCheck)]
    [RuleComputation(RuleComputationType.PerDiscover, 5)]
    [RuleANSSI("R18", "subsubsection.3.3.2")]
    [RuleMaturityLevel(2)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.ActiveDirectoryConfiguration)]
    public class HeatlcheckRulePrivilegedDangerousDelegation : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            foreach (HealthcheckDelegationData delegation in healthcheckData.Delegations)
            {
                if (delegation.Right.Contains("EXT_RIGHT_REANIMATE_TOMBSTONE") || delegation.Right.Contains("EXT_RIGHT_UNEXPIRE_PASSWORD") || delegation.Right.Contains("EXT_RIGHT_MIGRATE_SID_HISTORY"))
                {
                    AddRawDetail(delegation.DistinguishedName, delegation.Account, delegation.Right);
                }
            }
            return null;
        }
    }
}
