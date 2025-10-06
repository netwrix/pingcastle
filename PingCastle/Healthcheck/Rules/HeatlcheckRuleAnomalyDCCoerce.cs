//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-DC-Coerce", RiskRuleCategory.Anomalies, RiskModelCategory.PassTheCredential)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 10)]
    [RuleIntroducedIn(3, 1, 5, 1)]
    [RuleMaturityLevel(3)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.ForcedAuthentication)]
    public class HeatlcheckRuleAnomalyDCCoerce : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            foreach (var policy in healthcheckData.GPOLsaPolicy)
            {
                if (!healthcheckData.GPOInfoDic.ContainsKey(policy.GPOId))
                {
                    continue;
                }
                var refGPO = healthcheckData.GPOInfoDic[policy.GPOId];
                if (refGPO.IsDisabled)
                {
                    continue;
                }
                if (refGPO.AppliedTo == null && refGPO.AppliedTo.Count == 0)
                    continue;

                bool DCOrRoot = false;
                foreach (var a in refGPO.AppliedTo)
                {
                    if (a.Contains("OU=Domain Controllers,DC=") || a.StartsWith("DC="))
                    {
                        DCOrRoot = true;
                        break;
                    }
                }
                if (!DCOrRoot)
                    continue;

                foreach (var p in policy.Properties)
                {
                    if (string.Equals(p.Property, @"MSV1_0\RestrictSendingNTLMTraffic", System.StringComparison.OrdinalIgnoreCase))
                    {
                        if (p.Value == 2)
                        {
                            // found the GPO  Network security: Restrict NTLM: Add remote server exceptions for NTLM authentication set to "enabled"
                            // ignore the rule
                            return null;
                        }
                    }
                }
            }
            // else, list all dangerous RPC service available
            foreach (var DC in healthcheckData.DomainControllers)
            {
                if (DC.RPCInterfacesOpen != null)
                {
                    foreach (var rpc in DC.RPCInterfacesOpen)
                    {
                        // DCName: {0} IP: {1} Interface: {2} Function: {3} OpNum:
                        AddRawDetail(DC.DCName, rpc.IP, rpc.Interface, rpc.Function, rpc.OpNum);
                    }
                }
            }
            return null;
        }
    }
}
