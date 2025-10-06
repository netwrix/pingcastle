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
    [RuleModel("P-DisplaySpecifier", RiskRuleCategory.PrivilegedAccounts, RiskModelCategory.AccountTakeOver)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 10)]
    [RuleDurANSSI(1, "display_specifier", "Dangerous Display Specifiers")]
    [RuleMitreAttackTechnique(MitreAttackTechnique.SystemServices)]
    [RuleIntroducedIn(2, 11, 2)]
    public class HeatlcheckRulePrivilegedDisplaySpecifier : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.DisplaySpecifier != null)
            {
                foreach (var entry in healthcheckData.DisplaySpecifier)
                {
                    if (string.IsNullOrEmpty(entry.AdminContextMenu))
                        continue;
                    var e = entry.AdminContextMenu.Split(',');
                    if (e.Length < 3)
                        continue;
                    var path = e[2].Trim();

                    if (!path.Contains("\\\\"))
                        continue;

                    if (path.StartsWith("\"", StringComparison.OrdinalIgnoreCase) && path.EndsWith("\"", StringComparison.OrdinalIgnoreCase))
                        path = path.Substring(1, path.Length - 2);

                    if (!path.StartsWith("\\\\" + healthcheckData.DomainFQDN + "\\sysvol\\", StringComparison.OrdinalIgnoreCase) &&
                        !path.StartsWith("\\\\" + healthcheckData.ForestFQDN + "\\sysvol\\", StringComparison.OrdinalIgnoreCase))
                    {
                        AddRawDetail(entry.DN, entry.AdminContextMenu, entry.WhenChanged.ToString("u"));
                    }
                }
            }
            return null;
        }

        public static string IsScriptNotInSysvol(string uristring, HealthcheckData healthcheckData)
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
