//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//

using System;
using System.Collections.Generic;
using PingCastle.Rules;

namespace PingCastle.HealthCheck.Rules
{
    [RuleModel("P-LoginDCEveryone", RiskRuleCategory.PrivilegedAccounts, RiskModelCategory.ACLCheck)]
    [RuleComputation(RuleComputationType.PerDiscover, 15)]
    [RuleANSSI("R18", "subsubsection.3.3.2")]
    [RuleIntroducedIn(2, 7)]
    [RuleMaturityLevel(1)]
    public class HealthCheckRulePrivilegedLoginDCEveryone : RuleBase<HealthCheckData>
    {
        protected override int? AnalyzeDataNew(HealthCheckData healthcheckData)
        {
            var dangerousPrivileges = new List<string>()
            {
                "SeInteractiveLogonRight",
                "SeRemoteInteractiveLogonRight"
            };
            foreach (var privilege in healthcheckData.GPPLoginAllowedOrDeny)
            {
                if (privilege.User == "Authenticated Users" || privilege.User == "Everyone" || privilege.User == "Domain Users"
                    || privilege.User == "Domain Computers" || privilege.User == "Users"
                    || privilege.User == "Anonymous")
                {
                    foreach (var gpo in healthcheckData.GPOInfo)
                    {
                        if (string.Equals(gpo.GPOId, privilege.GPOId, StringComparison.OrdinalIgnoreCase))
                        {
                            bool appliedToDC = false;
                            foreach (var ou in gpo.AppliedTo)
                            {
                                if (ou.Contains("OU=Domain Controllers,"))
                                {
                                    appliedToDC = true;
                                    break;
                                }
                            }
                            if (appliedToDC)
                            {
                                // check if privilege is part of dangerous privilege
                                foreach (var p in dangerousPrivileges)
                                {
                                    if (string.Equals(privilege.Privilege, p, StringComparison.OrdinalIgnoreCase))
                                    {
                                        AddRawDetail(privilege.GPOName, privilege.User, privilege.Privilege);
                                    }
                                }
                            }
                            break;
                        }
                    }
                }
            }
            return null;
        }
    }
}