//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;
using System;
using System.Diagnostics;
using System.Net;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("T-ScriptOutOfDomain", RiskRuleCategory.Trusts, RiskModelCategory.TrustImpermeability)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 10)]
    [RuleMaturityLevel(2)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.ExploitationofRemoteServices)]
    public class HeatlcheckRuleTrustLoginScriptOutOfDomain : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            foreach (HealthcheckLoginScriptData script in healthcheckData.LoginScript)
            {
                if (IsForeignScript(script.LoginScript, healthcheckData) != null)
                {
                    Trace.WriteLine("Foreignscript:" + script.LoginScript);
                    AddRawDetail(script.LoginScript);
                }
            }
            foreach (HealthcheckGPOLoginScriptData script in healthcheckData.GPOLoginScript)
            {
                if (IsForeignScript(script.CommandLine, healthcheckData) != null)
                {
                    Trace.WriteLine("Foreignscript:" + script.CommandLine);
                    AddRawDetail(script.CommandLine);
                }
            }
            return null;
        }

        public static string IsForeignScript(string uristring, HealthcheckData healthcheckData)
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
                // try to find url matching server.domain.fqdn
                if (uri.IsUnc && uri.Host.Contains("."))
                {
                    IPAddress a;
                    // exclude IP Address
                    if (IPAddress.TryParse(uri.Host, out a))
                    {
                        return null;
                    }

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
