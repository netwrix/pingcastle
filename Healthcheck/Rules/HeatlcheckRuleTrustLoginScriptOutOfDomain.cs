//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace PingCastle.Healthcheck.Rules
{
	[HeatlcheckRuleModel("T-ScriptOutOfDomain", HealthcheckRiskRuleCategory.Trusts, HealthcheckRiskModelCategory.TrustImpermeability)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnPresence, 10)]
    public class HeatlcheckRuleTrustLoginScriptOutOfDomain : HeatlcheckRuleBase
    {
		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            foreach (HealthcheckLoginScriptData script in healthcheckData.LoginScript)
            {
                if (IsForeignScript(script.LoginScript, healthcheckData))
                {
                    Trace.WriteLine("Foreignscript:" + script.LoginScript);
                    AddRawDetail(script.LoginScript);
                }
            }
            foreach (HealthcheckGPOLoginScriptData script in healthcheckData.GPOLoginScript)
            {
                if (IsForeignScript(script.CommandLine, healthcheckData))
                {
                    Trace.WriteLine("Foreignscript:" + script.CommandLine);
					AddRawDetail(script.CommandLine);
                }
            }
            return null;
        }

        private bool IsForeignScript(string uristring, HealthcheckData healthcheckData)
        {
            if (uristring.StartsWith("\\\\", StringComparison.InvariantCultureIgnoreCase))
            {
                Uri uri;
                if (!Uri.TryCreate(uristring.Split(' ')[0], UriKind.RelativeOrAbsolute, out uri))
                {
                    Trace.WriteLine("Unable to parse the url: " + uristring);
                    return false;
                }
                if (uri.IsUnc && uri.Host.Contains("."))
                {
                    string server = uri.Host;
                    if (server.EndsWith(healthcheckData.DomainFQDN, StringComparison.InvariantCultureIgnoreCase)
                        || server.EndsWith(healthcheckData.ForestFQDN, StringComparison.InvariantCultureIgnoreCase))
                    {
                        return false;
                    }
                    return true;
                }
            }
            return false;
        }
    }
}
