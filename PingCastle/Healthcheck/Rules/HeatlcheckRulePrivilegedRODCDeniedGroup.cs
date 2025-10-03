using PingCastle.Graph.Reporting;
//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;
using System;
using System.Collections.Generic;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("P-RODCDeniedGroup", RiskRuleCategory.PrivilegedAccounts, RiskModelCategory.RODC)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 5)]
    [RuleIntroducedIn(2, 9)]
    [RuleDurANSSI(3, "rodc_denied_group", "Dangerous configuration of replication groups for read-only domain controllers (RODCs) (denied)")]
    [RuleMitreAttackMitigation(MitreAttackMitigation.ActiveDirectoryConfiguration)]
    public class HeatlcheckRulePrivilegedRODCDeniedGroup : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.DomainFunctionalLevel < 3)
                return 0;

            var mandatoryDN = new Dictionary<string, string>();

            mandatoryDN.Add(healthcheckData.DomainSid + "-516", "Domain Controllers");
            mandatoryDN.Add(healthcheckData.DomainSid + "-521", "Read Only Domain Controllers");
            mandatoryDN.Add(healthcheckData.DomainSid + "-520", "Group Policy Creator Owners");
            mandatoryDN.Add(healthcheckData.DomainSid + "-512", GraphObjectReference.DomainAdministrators);
            mandatoryDN.Add(healthcheckData.DomainSid + "-517", "Cert Publishers");
            mandatoryDN.Add(healthcheckData.DomainSid + "-502", "Krbtgt account");
            if (string.Equals(healthcheckData.ForestFQDN, healthcheckData.DomainFQDN, StringComparison.InvariantCultureIgnoreCase))
            {
                mandatoryDN.Add(healthcheckData.DomainSid + "-519", GraphObjectReference.EnterpriseAdministrators);
                mandatoryDN.Add(healthcheckData.DomainSid + "-518", GraphObjectReference.SchemaAdministrators);
            }

            foreach (var member in healthcheckData.DeniedRODCPasswordReplicationGroup)
            {
                if (mandatoryDN.ContainsKey(member))
                    mandatoryDN.Remove(member);
            }
            foreach (var missing in mandatoryDN.Values)
            {
                AddRawDetail(missing);
            }
            return null;
        }
    }
}
