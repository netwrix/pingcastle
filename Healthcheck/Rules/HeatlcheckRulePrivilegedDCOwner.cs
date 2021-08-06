//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;
using System.Security.Principal;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("P-DCOwner", RiskRuleCategory.PrivilegedAccounts, RiskModelCategory.ACLCheck)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 10)]
    [RuleDurANSSI(3, "owner", "Incorrect object owners")]
    [RuleMitreAttackMitigation(MitreAttackMitigation.PrivilegedAccountManagement)]
    public class HeatlcheckRulePrivilegedDCOwner : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.DomainControllers != null)
            {
                foreach (var DC in healthcheckData.DomainControllers)
                {
                    if (string.IsNullOrEmpty(DC.OwnerSID))
                        continue;
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
