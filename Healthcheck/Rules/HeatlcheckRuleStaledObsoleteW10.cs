//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;
using System;
using System.Text.RegularExpressions;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("S-OS-W10", RiskRuleCategory.StaleObjects, RiskModelCategory.ObsoleteOS)]
    [RuleComputation(RuleComputationType.TriggerOnThreshold, 15, Threshold: 15, Order: 1)]
    [RuleComputation(RuleComputationType.TriggerOnThreshold, 10, Threshold: 6, Order: 2)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 5, Order: 3)]
    [RuleCERTFR("CERTFR-2005-INF-003", "SECTION00032400000000000000")]
    [RuleMaturityLevel(2)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.UpdateSoftware)]
    [RuleIntroducedIn(2, 9, 3)]
    public class HeatlcheckRuleStaledObsoleteW10 : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            ReplacementToDo.Clear();
            int totalActive = 0;
            foreach (var osVersion in healthcheckData.OperatingSystemVersion)
            {
                if (!osVersion.IsServer)
                {
                    if (osVersion.data.NumberEnabled == 0)
                        continue;

                    Regex re = new Regex("(?<major>\\d+).(?<minor>\\d+) \\((?<release>\\d+)\\)");
                    var m = re.Match(osVersion.OSVersion);
                    if (!m.Success)
                        continue;
                    int major = int.Parse(m.Groups["major"].Value);
                    int minor = int.Parse(m.Groups["minor"].Value);
                    int release = int.Parse(m.Groups["release"].Value);
                    if (major == 10 && minor == 0)
                    {
                        // see https://learn.microsoft.com/en-us/windows/release-health/release-information
                        // and https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information
                        switch (release)
                        {
                            case 22631:
                                if (healthcheckData.GenerationDate > new DateTime(2026, 11, 10))
                                {
                                    AddRawDetail("Windows 11 23H2", osVersion.data.Number, osVersion.data.NumberActive);
                                    totalActive += osVersion.data.NumberActive;
                                }
                                break;
                            case 22621:
                                if (healthcheckData.GenerationDate > new DateTime(2025, 10, 14))
                                {
                                    AddRawDetail("Windows 11 22H2", osVersion.data.Number, osVersion.data.NumberActive);
                                    totalActive += osVersion.data.NumberActive;
                                }
                                break;
                            case 22000:
                                if (healthcheckData.GenerationDate > new DateTime(2024, 10, 08))
                                {
                                    AddRawDetail("Windows 11 21H2", osVersion.data.Number, osVersion.data.NumberActive);
                                    totalActive += osVersion.data.NumberActive;
                                }
                                break;
                            case 19045:
                                if (healthcheckData.GenerationDate > new DateTime(2025, 10, 14))
                                {
                                    AddRawDetail("Windows 10 22H2", osVersion.data.Number, osVersion.data.NumberActive);
                                    totalActive += osVersion.data.NumberActive;
                                }
                                break;
                            case 19044:
                                if (osVersion.IsLTSC)
                                {
                                    if (osVersion.IsIOT)
                                    {
                                        if (healthcheckData.GenerationDate > new DateTime(2032, 01, 13))
                                        {
                                            AddRawDetail("Windows 10 21H2 IOT LTSC", osVersion.data.Number, osVersion.data.NumberActive);
                                            totalActive += osVersion.data.NumberActive;
                                        }
                                    }
                                    else if (healthcheckData.GenerationDate > new DateTime(2027, 01, 12))
                                    {
                                        AddRawDetail("Windows 10 21H2 LTSC", osVersion.data.Number, osVersion.data.NumberActive);
                                        totalActive += osVersion.data.NumberActive;
                                    }
                                }
                                else
                                {
                                    if (healthcheckData.GenerationDate > new DateTime(2024, 06, 11))
                                    {
                                        AddRawDetail("Windows 10 21H2", osVersion.data.Number, osVersion.data.NumberActive);
                                        totalActive += osVersion.data.NumberActive;
                                    }
                                }
                                break;
                            case 19043:
                                if (healthcheckData.GenerationDate > new DateTime(2022, 12, 13))
                                {
                                    AddRawDetail("Windows 10 21H1", osVersion.data.Number, osVersion.data.NumberActive);
                                    totalActive += osVersion.data.NumberActive;
                                }
                                break;
                            case 19042:
                                if (healthcheckData.GenerationDate > new DateTime(2023, 05, 09))
                                {
                                    AddRawDetail("Windows 10 20H2", osVersion.data.Number, osVersion.data.NumberActive);
                                    totalActive += osVersion.data.NumberActive;
                                }
                                break;
                            case 19041:
                                if (healthcheckData.GenerationDate > new DateTime(2021, 12, 14))
                                {
                                    AddRawDetail("Windows 10 2004", osVersion.data.Number, osVersion.data.NumberActive);
                                    totalActive += osVersion.data.NumberActive;
                                }
                                break;
                            case 18363:
                                if (healthcheckData.GenerationDate > new DateTime(2022, 05, 10))
                                {
                                    AddRawDetail("Windows 10 1909", osVersion.data.Number, osVersion.data.NumberActive);
                                    totalActive += osVersion.data.NumberActive;
                                }
                                break;
                            case 18362:
                                AddRawDetail("Windows 10 1903", osVersion.data.Number, osVersion.data.NumberActive);
                                totalActive += osVersion.data.NumberActive;
                                break;
                            case 18356:
                            case 18908:
                                AddRawDetail("Windows 10 " + release + " (insider)", osVersion.data.Number, osVersion.data.NumberActive);
                                totalActive += osVersion.data.NumberActive;
                                break;
                            case 17763:
                                if (osVersion.IsLTSC)
                                {
                                    if (osVersion.IsIOT)
                                    {
                                        if (healthcheckData.GenerationDate > new DateTime(2029, 01, 09))
                                        {
                                            AddRawDetail("Windows 10 1809 IOT LTSC", osVersion.data.Number, osVersion.data.NumberActive);
                                            totalActive += osVersion.data.NumberActive;
                                        }
                                    }
                                    else if (healthcheckData.GenerationDate > new DateTime(2029, 01, 09))
                                    {
                                        AddRawDetail("Windows 10 1809 LTSC", osVersion.data.Number, osVersion.data.NumberActive);
                                        totalActive += osVersion.data.NumberActive;
                                    }
                                }
                                else
                                {
                                    AddRawDetail("Windows 10 1809", osVersion.data.Number, osVersion.data.NumberActive);
                                    totalActive += osVersion.data.NumberActive;
                                }
                                break;
                            case 17134:
                                AddRawDetail("Windows 10 1803", osVersion.data.Number, osVersion.data.NumberActive);
                                totalActive += osVersion.data.NumberActive;
                                break;
                            case 16299:
                                AddRawDetail("Windows 10 1709", osVersion.data.Number, osVersion.data.NumberActive);
                                totalActive += osVersion.data.NumberActive;
                                break;
                            case 15063:
                                AddRawDetail("Windows 10 1703", osVersion.data.Number, osVersion.data.NumberActive);
                                totalActive += osVersion.data.NumberActive;
                                break;
                            case 14393:
                                if (osVersion.IsLTSC)
                                {
                                    if (osVersion.IsIOT)
                                    {
                                        if (healthcheckData.GenerationDate > new DateTime(2026, 10, 13))
                                        {
                                            AddRawDetail("Windows 10 1607 IOT LTSC", osVersion.data.Number, osVersion.data.NumberActive);
                                            totalActive += osVersion.data.NumberActive;
                                        }
                                    }
                                    else if (healthcheckData.GenerationDate > new DateTime(2026, 09, 13))
                                    {
                                        AddRawDetail("Windows 10 1607 LTSC", osVersion.data.Number, osVersion.data.NumberActive);
                                        totalActive += osVersion.data.NumberActive;
                                    }
                                }
                                else
                                {
                                    AddRawDetail("Windows 10 1607", osVersion.data.Number, osVersion.data.NumberActive);
                                    totalActive += osVersion.data.NumberActive;
                                }
                                break;
                            case 10586:
                                AddRawDetail("Windows 10 1511", osVersion.data.Number, osVersion.data.NumberActive);
                                totalActive += osVersion.data.NumberActive;
                                break;
                            case 10240:
                                if (osVersion.IsIOT)
                                {
                                    if (healthcheckData.GenerationDate > new DateTime(2025, 10, 14))
                                    {
                                        AddRawDetail("Windows 10 1507 IOT LTSC", osVersion.data.Number, osVersion.data.NumberActive);
                                        totalActive += osVersion.data.NumberActive;
                                    }
                                }
                                else
                                {
                                    AddRawDetail("Windows 10 1507", osVersion.data.Number, osVersion.data.NumberActive);
                                    totalActive += osVersion.data.NumberActive;
                                }
                                break;
                        }
                    }
                }
            }
            ReplacementToDo["{activeComputers}"] = totalActive.ToString();
            return null;
        }
    }
}
