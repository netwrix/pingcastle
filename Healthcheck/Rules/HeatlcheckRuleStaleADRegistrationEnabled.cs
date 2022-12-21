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
    [RuleMaturityLevel(3)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.UserAccountManagement)]
    public class HeatlcheckRuleStaleADRegistrationEnabled : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.MachineAccountQuota == 0)
            {
                return 0;
            }
            var gpo = new Dictionary<GPOInfo, bool>();
            foreach (GPPRightAssignment right in healthcheckData.GPPRightAssignment)
            {
                if (string.IsNullOrEmpty(right.GPOId))
                {
                    continue;
                }
                if (healthcheckData.GPOInfoDic == null || !healthcheckData.GPOInfoDic.ContainsKey(right.GPOId))
                {
                    continue;
                }
                var refGPO = healthcheckData.GPOInfoDic[right.GPOId];
                if (refGPO.IsDisabled)
                {
                    continue;
                }
                if (refGPO.AppliedTo == null || refGPO.AppliedTo.Count == 0)
                {
                    continue;
                }
                if (right.Privilege == "SeMachineAccountPrivilege")
                {
                    if (right.User == GraphObjectReference.Everyone
                        || right.User == GraphObjectReference.AuthenticatedUsers
                        || right.User == GraphObjectReference.Users
                        || right.User == GraphObjectReference.Anonymous
                        )
                    {
                        Trace.WriteLine("SeMachineAccountPrivilege found in GPO 1 " + right.GPOName);
                        gpo[refGPO] = true;
                    }
                    else
                    {
                        Trace.WriteLine("SeMachineAccountPrivilege found in GPO 2 " + right.GPOName);
                        gpo[refGPO] = false;
                    }
                }
            }
            if (gpo.Count == 0)
                return healthcheckData.MachineAccountQuota;
            var applied = new Dictionary<string, Dictionary<int, bool>>();
            foreach (var v in gpo.Keys)
            {
                for (int i = 0; i < v.AppliedTo.Count; i++)
                {
                    var a = v.AppliedTo[i];
                    int order = 0;
                    if (v.AppliedOrder != null && v.AppliedOrder.Count > i)
                    {
                        order = v.AppliedOrder[i];
                    }
                    if (!applied.ContainsKey(a))
                        applied[a] = new Dictionary<int, bool>();
                    applied[a][order] = gpo[v];
                }
            }
            var applied2 = new Dictionary<string, bool>();
            foreach (var a in applied.Keys)
            {
                var min = int.MaxValue;
                var w = false;
                foreach (var v in applied[a])
                {
                    if (v.Key < min)
                    {
                        w = v.Value;
                    }
                }
                applied2[a] = w;
            }
            foreach (var v in applied2)
            {
                if (v.Value == true)
                    return healthcheckData.MachineAccountQuota;
            }
            return 0;
        }
    }
}
