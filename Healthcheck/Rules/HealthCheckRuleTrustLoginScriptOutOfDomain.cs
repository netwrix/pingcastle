﻿//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//

using System;
using System.Diagnostics;
using PingCastle.Rules;

namespace PingCastle.HealthCheck.Rules
{
    [RuleModel("T-ScriptOutOfDomain", RiskRuleCategory.Trusts, RiskModelCategory.TrustImpermeability)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 10)]
    [RuleMaturityLevel(2)]
    public class HealthCheckRuleTrustLoginScriptOutOfDomain : RuleBase<HealthCheckData>
    {
        protected override int? AnalyzeDataNew(HealthCheckData healthcheckData)
        {
            foreach (HealthCheckLoginScriptData script in healthcheckData.LoginScript)
            {
                if (IsForeignScript(script.LoginScript, healthcheckData) != null)
                {
                    Trace.WriteLine("Foreignscript:" + script.LoginScript);
                    AddRawDetail(script.LoginScript);
                }
            }
            foreach (HealthCheckGPOLoginScriptData script in healthcheckData.GPOLoginScript)
            {
                if (IsForeignScript(script.CommandLine, healthcheckData) != null)
                {
                    Trace.WriteLine("Foreignscript:" + script.CommandLine);
                    AddRawDetail(script.CommandLine);
                }
            }
            return null;
        }

        public static string IsForeignScript(string uristring, HealthCheckData healthcheckData)
        {
            if (uristring.StartsWith("\\\\", StringComparison.InvariantCultureIgnoreCase))
            {
                Uri uri;
                if (!Uri.TryCreate(uristring.Split(' ')[0], UriKind.RelativeOrAbsolute, out uri))
                {
                    Trace.WriteLine("Unable to parse the url: " + uristring);
                    return null;
                }

                // important, to avoid an exception in uri.IsUnc
                if (!uri.IsAbsoluteUri)
                {
                    Trace.WriteLine("The url is not absolute: " + uristring);
                    return null;
                }
                if (uri.IsUnc && uri.Host.Contains("."))
                {
                    string server = uri.Host;
                    if (server.EndsWith(healthcheckData.DomainFQDN, StringComparison.InvariantCultureIgnoreCase)
                        || server.EndsWith(healthcheckData.ForestFQDN, StringComparison.InvariantCultureIgnoreCase))
                    {
                        return null;
                    }
                    return server;
                }
            }
            return null;
        }
    }
}