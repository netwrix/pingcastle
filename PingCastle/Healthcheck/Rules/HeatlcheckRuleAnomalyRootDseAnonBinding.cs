//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;
using System.Diagnostics;
using System.Text.RegularExpressions;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-RootDseAnonBinding", RiskRuleCategory.Anomalies, RiskModelCategory.Reconnaissance)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 0)]
    [RuleMaturityLevel(5)]
    [RuleIntroducedIn(3, 3)]
    [RuleMitreAttackTechnique(MitreAttackTechnique.RemoteSystemDiscovery)]
    public class HeatlcheckRuleAnomalyRootDseAnonBinding : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            int DenyUnauthenticatedBind = 0;
            // see https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/41cbdb2c-eab1-45b0-8236-ae777b1c5406
            // MS-ADTS 3.1.1.3.4.7 LDAP Configurable Settings
            if (healthcheckData.DSOtherSettings != null)
            {
                foreach (var value in healthcheckData.DSOtherSettings)
                {
                    var v = value.Split('=');
                    if (v.Length == 2)
                    {
                        if (string.Equals(v[0], "DenyUnauthenticatedBind", System.StringComparison.OrdinalIgnoreCase))
                        {
                            if (!int.TryParse(v[1], out DenyUnauthenticatedBind))
                            {
                                Trace.WriteLine("Incorrect value for " + value);
                            }
                        }
                    }
                }
            }
            // if option is set, stop the rule evaluation here
            if (DenyUnauthenticatedBind == 1)
                return 0;
            // check DC OS for support
            if (healthcheckData.DomainControllers != null)
            {
                foreach (var dc in healthcheckData.DomainControllers)
                {
                    if (string.IsNullOrEmpty(dc.OperatingSystemVersion))
                        continue;

                    // write this algorithm to support later version of Windows Server
                    Regex re = new Regex("(?<major>\\d+).(?<minor>\\d+) \\((?<release>\\d+)\\)");
                    var m = re.Match(dc.OperatingSystemVersion);
                    if (!m.Success)
                        continue;

                    int major = int.Parse(m.Groups["major"].Value);
                    int minor = int.Parse(m.Groups["minor"].Value);
                    int release = int.Parse(m.Groups["release"].Value);

                    // Windows 2019 is 10.0 (17763)
                    if (major > 10)
                    {
                        return 1;
                    }
                    if (major == 10 && minor > 0)
                    {
                        return 1;
                    }
                    if (major == 10 && minor == 0 && release >= 17763)
                    {
                        return 1;
                    }
                }
            }
            return 0;
        }
    }
}
