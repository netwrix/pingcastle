//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;
using System.Collections.Generic;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("S-TerminalServicesGPO", RiskRuleCategory.StaleObjects, RiskModelCategory.ObjectConfig)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 0)]
    [RuleIntroducedIn(3, 3, 0)]
    [RuleMaturityLevel(4)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.ActiveDirectoryConfiguration)]
    public class HeatlcheckRuleStaledTerminalServiceGPO : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            var gpo = new Dictionary<IGPOReference, int>();
            var gpo2 = new Dictionary<IGPOReference, int>();
            var gpo3 = new Dictionary<IGPOReference, bool>();

            if (healthcheckData.GPPTerminalServiceConfigs != null)
            {
                foreach (var policy in healthcheckData.GPPTerminalServiceConfigs)
                {
                    if (policy.MaxIdleTime != null)
                    {
                        gpo.Add(policy, policy.MaxIdleTime.Value);
                    }
                    if (policy.MaxDisconnectionTime != null)
                    {
                        gpo2.Add(policy, policy.MaxDisconnectionTime.Value);
                    }
                    if (policy.fDisableCpm != null)
                    {
                        gpo3.Add(policy, policy.fDisableCpm.Value);
                    }

                }
            }

            var o = ApplyGPOPrority2(healthcheckData, gpo);
            var o2 = ApplyGPOPrority2(healthcheckData, gpo2);
            var o3 = ApplyGPOPrority2(healthcheckData, gpo3);

            bool found = false;
            bool found2 = false;
            bool found3 = false;

            foreach (var v in o)
            {
                found = true;
                if (v.Value == 0)
                {
                    AddRawDetail(v.Key.GPOName, "MaxIdleTime is set to NEVER");
                }
            }
            foreach (var v in o2)
            {
                found2 = true;
                if (v.Value == 0)
                {
                    AddRawDetail(v.Key.GPOName, "MaxDisconnectionTime is set to NEVER");
                }
            }
            foreach (var v in o3)
            {
                found3 = true;
                if (!v.Value)
                {
                    AddRawDetail(v.Key.GPOName, "fDisableCpm is set to NEVER");
                }
            }

            if (!found)
            {
                AddRawDetail("Windows default without an active GPO", "MaxIdleTime is not set");
            }
            if (!found2)
            {
                AddRawDetail("Windows default without an active GPO", "MaxDisconnectionTime is not set");
            }
            if (!found3)
            {
                AddRawDetail("Windows default without an active GPO", "fDisableCpm is not set");
            }
            return null;
        }
    }
}
