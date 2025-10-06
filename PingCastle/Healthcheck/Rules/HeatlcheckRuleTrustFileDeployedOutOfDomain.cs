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
    [RuleModel("T-FileDeployedOutOfDomain", RiskRuleCategory.Trusts, RiskModelCategory.TrustImpermeability)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 10)]
    [RuleIntroducedIn(2, 7)]
    [RuleMaturityLevel(2)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.ExploitationofRemoteServices)]
    public class HeatlcheckRuleTrustFileDeployedOutOfDomain : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            var data = new Dictionary<string, List<KeyValuePair<string, string>>>();
            foreach (var file in healthcheckData.GPPFileDeployed)
            {
                string domain = HeatlcheckRuleTrustLoginScriptOutOfDomain.IsForeignScript(file.FileName, healthcheckData);
                if (domain != null)
                {
                    Trace.WriteLine("File:" + file.FileName);
                    if (!data.ContainsKey(domain))
                        data[domain] = new List<KeyValuePair<string, string>>();
                    data[domain].Add(new KeyValuePair<string, string>(file.GPOName, file.FileName));
                }
            }
            foreach (var domain in data.Keys)
            {
                AddRawDetail(domain, string.Join(",", data[domain].ConvertAll(k => k.Key).ToArray()), string.Join(",", data[domain].ConvertAll(k => k.Value).ToArray()));
            }
            return null;
        }
    }
}
