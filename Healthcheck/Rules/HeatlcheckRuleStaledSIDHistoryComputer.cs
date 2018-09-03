using System;
using System.Collections.Generic;
using System.Text;

namespace ADSecurityHealthCheck.Healthcheck.Rules
{
    public class HeatlcheckRuleStaledSIDHistoryComputer : HeatlcheckRuleBase
    {
        public HeatlcheckRuleStaledSIDHistoryComputer()
        {
            Category = HealthcheckRiskRuleCategory.StaleObjects;
            Id = "S-C-SIDHistory";
            Description = @"Check SIDHistory";
            Solution = @"SID History is an attribute used when migrating users or computers from one domain to another
It can be used to take control of foreign domain or setting backdoors.
You can list the objects using the command:
Get-ADObject -ldapfilter ""(sidhistory=*)"" -properties sidhistory
The SIDHistory attribute can then be removed using the migration tool or the powershell snippet Remove-SIDHistory";
            Points = 15;
        }
        public override bool Analyze(HealthcheckData healthcheckData)
        {
            if (healthcheckData.ComputerAccountData.NumberSidHistory > 0)
            {
                if (healthcheckData.ComputerAccountData.NumberSidHistory * 100 > healthcheckData.ComputerAccountData.Number * 10)
                    Points = 30;
                else
                    Points = 15;
                Rationale = "Computer accounts with SID History = " + healthcheckData.ComputerAccountData.NumberSidHistory + " (migration should be completed)";
                return true;
            }
            return false;
        }
    }
}
