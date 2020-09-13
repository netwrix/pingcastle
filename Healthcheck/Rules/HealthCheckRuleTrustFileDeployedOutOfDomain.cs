//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//

using System.Collections.Generic;
using System.Diagnostics;
using PingCastle.Rules;

namespace PingCastle.HealthCheck.Rules
{
    [RuleModel("T-FileDeployedOutOfDomain", RiskRuleCategory.Trusts, RiskModelCategory.TrustImpermeability)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 10)]
    [RuleIntroducedIn(2, 7)]
    [RuleMaturityLevel(2)]
    public class HealthCheckRuleTrustFileDeployedOutOfDomain : RuleBase<HealthCheckData>
    {
        protected override int? AnalyzeDataNew(HealthCheckData healthcheckData)
        {
            var data = new Dictionary<string, List<KeyValuePair<string, string>>>();
            foreach (var file in healthcheckData.GPPFileDeployed)
            {
                string domain = HealthCheckRuleTrustLoginScriptOutOfDomain.IsForeignScript(file.FileName, healthcheckData);
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