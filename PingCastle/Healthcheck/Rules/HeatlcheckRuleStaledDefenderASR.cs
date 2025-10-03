//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("S-DefenderASR", RiskRuleCategory.StaleObjects, RiskModelCategory.ObjectConfig)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 0)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.ActiveDirectoryConfiguration)]
    [RuleMaturityLevel(5)]
    [RuleIntroducedIn(3, 3)]
    public class HeatlcheckRuleStaledDefenderASR : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            // This rule is dependent on Windows version.
            if (healthcheckData.OperatingSystemVersion == null)
            {
                return 0;
            }

            // ignore preview rules (for the moment)
            // Set capacity to nine as there will be either eight or nine entries in the dictionary, depending on the presence of the Block WebShell entry
            var expectedMitigations = new Dictionary<string, string>(9)
            {
                {"7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c","Block Adobe Reader from creating child processes"},
                {"9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2","Block credential stealing from the Windows local security authority subsystem (lsass.exe)"},
                {"be9ba2d9-53ea-4cdc-84e5-9b1eeee46550","Block executable content from email client and webmail"},
                {"d3e037e1-3eb8-44c8-a917-57927947596d","Block JavaScript or VBScript from launching downloaded executable content"},
                {"3b576869-a4ec-4529-8536-b80a7769e899","Block Office applications from creating executable content"},
                {"e6db77e5-3df2-4cf1-b95a-636979351e5b","Block persistence through WMI event subscription"},
                {"b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4","Block untrusted and unsigned processes that run from USB"},

                {"56a863a9-875e-4185-98a7-b882c64b5ce5","Block abuse of exploited vulnerable signed drivers"},
            };

            // Block WebShell is only relevant if there are Exchange Servers present.
            if (healthcheckData.ExchangeServers?.Count > 0)
            {
                expectedMitigations.Add("a8f5898e-1dc8-49a9-9878-85004b8a61e6", "Block Webshell creation for Servers");
            }

            var auditMitigations = new Dictionary<string, string>
            {
                {"75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84","Block Office applications from injecting code into other processes"},
                {"92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b","Block Win32 API calls from Office macros"},
                {"d4f940ab-401b-4efc-aadc-ad5f3c50688a","Block all Office applications from creating child processes"},
                {"5beb7efe-fd9a-4556-801d-275e5ffc04cc","Block execution of potentially obfuscated scripts"},

                {"01443614-cd74-433a-b99e-2ecdc07bfc25","Block executable files from running unless they meet a prevalence, age, or trusted list criterion"},
                {"c1db55ab-c21a-4637-bb3f-a12568109d35","Use advanced protection against ransomware"},
                {"d1e49aac-8f56-4280-b9ba-993a6d77406c","Block process creations originating from PSExec and WMI commands"},
                {"26190899-1602-49e8-8b27-eb1d0a1ce869","Block Office communication application from creating child processes"},

                {"33ddedf1-c6e0-47cb-833e-de6133960387","Block rebooting machine in Safe Mode (preview)"},
                {"c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb","Block use of copied or impersonated system tools (preview)"},
            };

            // decide if this rule should be enforce
            // criteria: 
            // server at least Windows 2012
            // Windows at least Windows 10

            bool enforce = false;
            foreach (var osVersion in healthcheckData.OperatingSystemVersion)
            {
                Regex re = new Regex("(?<major>\\d+).(?<minor>\\d+) \\((?<release>\\d+)\\)");
                var m = re.Match(osVersion.OSVersion);
                if (!m.Success)
                    continue;

                int major = int.Parse(m.Groups["major"].Value);
                int minor = int.Parse(m.Groups["minor"].Value);
                int release = int.Parse(m.Groups["release"].Value);

                if (osVersion.IsServer && (major > 6 || major == 6 && minor >= 3))
                {
                    enforce = true;
                    break;
                }

                if (!osVersion.IsServer && major >= 10)
                {
                    enforce = true;
                    break;
                }
            }

            if (!enforce)
            {
                return 0;
            }

            var foundAndBlocked = new List<string>();
            var foundAndNotBlocked = new List<string>();
            if (healthcheckData.GPODefenderASR != null)
            {
                foreach (var option in healthcheckData.GPODefenderASR)
                {
                    var asrRule = option.ASRRule.ToLowerInvariant();
                    if (option.Action == 1 || option.Action == 6)
                    {
                        if (!foundAndBlocked.Contains(asrRule))
                            foundAndBlocked.Add(asrRule);
                    }
                    else if (option.Action == 2)
                    {
                        if (!foundAndNotBlocked.Contains(asrRule))
                            foundAndNotBlocked.Add(asrRule);
                    }
                }
            }

            foreach (var ext in expectedMitigations)
            {
                if (!foundAndBlocked.Contains(ext.Key))
                {
                    if (!foundAndNotBlocked.Contains(ext.Key))
                    {
                        AddRawDetail(ext.Key, ext.Value, "Not found - Block or Warn recommended");
                    }
                    else
                    {
                        AddRawDetail(ext.Key, ext.Value, "Found (Audit) but not enforced (Block or Warn)");
                    }
                }
            }

            foreach (var ext in auditMitigations)
            {
                if (!foundAndBlocked.Contains(ext.Key) && !foundAndNotBlocked.Contains(ext.Key))
                {
                    AddRawDetail(ext.Key, ext.Value, "Not found - Audit recommended");
                }
            }
            return null;
        }
    }
}
