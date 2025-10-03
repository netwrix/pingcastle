using PingCastle.Graph.Reporting;
//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;
using System.Collections.Generic;
using System.Diagnostics;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("S-ADRegistration", RiskRuleCategory.StaleObjects, RiskModelCategory.Provisioning)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 10)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.UserAccountManagement)]
    [RuleDurANSSI(4, "user_accounts_machineaccountquota", "Unrestricted domain join")]
    public class HeatlcheckRuleStaleADRegistrationEnabled : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.MachineAccountQuota == 0)
            {
                return 0;
            }
            var gpo = new Dictionary<IGPOReference, List<string>>();
            foreach (GPPRightAssignment right in healthcheckData.GPPRightAssignment)
            {
                if (right.Privilege == "SeMachineAccountPrivilege")
                {
                    if (!gpo.ContainsKey(right))
                        gpo[right] = new List<string>();
                    gpo[right].Add(right.User);
                }
            }
            var o = ApplyGPOPrority2(healthcheckData, gpo);

            bool found = false;
            foreach (var v in o)
            {
                found = true;
                foreach (var user in v.Value)
                {
                    if (user == GraphObjectReference.Everyone
                           || user == GraphObjectReference.AuthenticatedUsers
                           || user == GraphObjectReference.Users
                           || user == GraphObjectReference.Anonymous
                           )
                    {
                        Trace.WriteLine("Found on " + v.Key.GPOName + " with " + v.Value);
                        return healthcheckData.MachineAccountQuota;
                    }
                }
            }

            // note: according to https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/add-workstations-to-domain if not GPO sets SeMachineAccountPrivilege it is assigned by DC to authenticated users.
            if (!found)
            {
                Trace.WriteLine("Defined in no GPO so default AD settings");
                return healthcheckData.MachineAccountQuota;
            }
            return 0;
        }
    }
}
