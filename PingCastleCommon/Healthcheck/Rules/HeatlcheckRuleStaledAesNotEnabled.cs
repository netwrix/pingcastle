//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;
using PingCastleCommon.Utility;
using System;
using System.Collections.Generic;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("S-AesNotEnabled", RiskRuleCategory.StaleObjects, RiskModelCategory.OldAuthenticationProtocols)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 10)]
    [RuleDurANSSI(3, "kerberos_properties_encryption", "Service accounts supported encryption algorithms")]
    [RuleMitreAttackTechnique(MitreAttackTechnique.StealorForgeKerberosTicketsASREPRoasting)]
    [RuleIntroducedIn(3, 3)]
    public class HeatlcheckRuleStaledAesNotEnabled : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            // ignore for older OS
            if (healthcheckData.DCWin2008Install == default(DateTime))
            {
                return 0;
            }

            var total = healthcheckData.UserAccountData.NumberNotAesEnabled + healthcheckData.ComputerAccountData.NumberNotAesEnabled;

            // detail rows drive the score when they are emitted, so the two paths stay mutually exclusive
            if (total < maxNumDisplayAccount)
            {
                AddAccountDetails(healthcheckData.UserAccountData.ListNotAesEnabled);
                AddAccountDetails(healthcheckData.ComputerAccountData.ListNotAesEnabled);
                return null;
            }

            return total;
        }

        private void AddAccountDetails(List<HealthcheckAccountDetailData> accounts)
        {
            // reports generated before the list was collected carry only the count
            if (accounts == null)
            {
                return;
            }

            for (int i = 0; i < accounts.Count; i++)
            {
                AddRawDetail(accounts[i].Name, KerberosEncryptionTypeHelper.ToReadableString(accounts[i].msDSSupportedEncryptionTypes));
            }
        }
    }
}
