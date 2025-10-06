//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.misc;
using PingCastle.Rules;
using System.Collections.Generic;
using System.Net;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("S-DC-SubnetMissing", RiskRuleCategory.StaleObjects, RiskModelCategory.NetworkTopography)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 5)]
    [RuleIntroducedIn(2, 5)]
    [RuleMaturityLevel(3)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.ActiveDirectoryConfiguration)]
    public class HeatlcheckRuleStaledDCSubnetMissing : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            var subnets = new List<Subnet>();
            foreach (var site in healthcheckData.Sites)
            {
                foreach (var subnet in site.Networks)
                {
                    IPAddress lowIP;
                    int bits;
                    var parts = subnet.Split('/');
                    if (parts.Length == 2 && IPAddress.TryParse(parts[0], out lowIP) && int.TryParse(parts[1], out bits))
                    {
                        subnets.Add(new Subnet(lowIP, bits));
                    }
                }
            }
            foreach (var dc in healthcheckData.DomainControllers)
            {
                if (dc.IP != null)
                {
                    foreach (string ip in dc.IP)
                    {
                        var ipaddress = IPAddress.Parse(ip);
                        if (ipaddress.IsIPv6LinkLocal || ipaddress.IsIPv6Multicast || ipaddress.IsIPv6SiteLocal)
                            continue;
                        bool found = false;
                        foreach (var subnet in subnets)
                        {
                            if (subnet.MatchIp(ipaddress))
                            {
                                found = true;
                                break;
                            }
                        }
                        if (!found)
                        {
                            AddRawDetail(dc.DCName, ip);
                        }
                    }
                }
            }
            return null;
        }
    }
}
