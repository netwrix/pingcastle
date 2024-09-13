//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.misc;
using PingCastle.Rules;
using System;
using System.Collections.Generic;
using System.Net;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("S-FirewallScript", RiskRuleCategory.StaleObjects, RiskModelCategory.NetworkTopography)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 0)]
    [RuleIntroducedIn(3, 3)]
    [RuleMaturityLevel(5)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.ActiveDirectoryConfiguration)]
    public class HeatlcheckRuleStaledScriptToInternet : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            var fwRules = new Dictionary<string, List<GPPFireWallRule>>() { 
                { "wscript.exe", null },
                { "mshta.exe", null },
                { "cscript.exe", null },
                { "conhost.exe", null },
                { "runScriptHelper.exe", null },
            };

            // assign all rules to programs to block
            if (healthcheckData.GPPFirewallRules != null)
            {
                foreach (var rule in healthcheckData.GPPFirewallRules)
                {
                    string program = null;
                    foreach (var f in fwRules.Keys)
                    {
                        if (string.IsNullOrEmpty(rule.App))
                            continue;
                        if (string.Equals(rule.App, f, System.StringComparison.OrdinalIgnoreCase) || rule.App.EndsWith("\\" + f, System.StringComparison.OrdinalIgnoreCase))
                        {
                            program = f;
                            break;
                        }
                    }
                    if (program == null)
                        continue;
                    if (fwRules[program] == null)
                        fwRules[program] = new List<GPPFireWallRule>();
                    fwRules[program].Add(rule);
                }
            }

            foreach (var program in fwRules.Keys)
            {
                var rules = fwRules[program];
                if (rules == null)
                {
                    AddRawDetail(program, "No Firewall rules found");
                    continue;
                }
                else
                {
                    var RA4 = new List<string>();
                    foreach (var rule in rules)
                    {
                        if (!rule.Active)
                            continue;
                        if (!string.Equals(rule.Action, "Block", System.StringComparison.OrdinalIgnoreCase))
                            continue;
                        if (rule.RA4 == null && rule.RA6 == null)
                            rule.RA4 = new List<string>() { "0.0.0.0-255.255.255.255" };
                        if (!string.Equals(rule.Direction, "Out", System.StringComparison.OrdinalIgnoreCase))
                            continue;
                        if (rule.RA4 != null)
                            RA4.AddRange(rule.RA4);
                    }
                    if (RA4.Count == 0)
                    {
                        AddRawDetail(program, "Firewall rules found but not in application");
                        continue;
                    }
                    string Reason = CheckCompliance(RA4);
                    if (!string.IsNullOrEmpty(Reason))
                    {
                        AddRawDetail(program, "Firewall rules have been identified and are currently in application. " + Reason);
                        continue;
                    }
                }
            }

            return null;
        }

        private string CheckCompliance(List<string> RA4)
        {
            var subnetsIPV4 = new List<Subnet>();
            foreach (var address in RA4)
            {
                IPAddress lowIP;
                IPAddress highIP;
                int bits;

                if (address.Contains("/"))
                {
                    var parts = address.Split('/');
                    if (parts.Length == 2 && IPAddress.TryParse(parts[0], out lowIP) && int.TryParse(parts[1], out bits)
                        && lowIP.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        subnetsIPV4.Add(new Subnet(lowIP, bits));
                    }
                }
                else if (address.Contains("-"))
                {
                    var parts = address.Split('-');
                    if (parts.Length == 2 && IPAddress.TryParse(parts[0], out lowIP) && IPAddress.TryParse(parts[1], out highIP)
                        && lowIP.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && highIP.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        subnetsIPV4.Add(new Subnet(lowIP, highIP));
                    }
                }
                else if (IPAddress.TryParse(address, out lowIP))
                {
                    // ignore because we need ranges for the computation
                }
                else
                {
                    // other predefined configuration such as "WINS"
                }
            }

            if (subnetsIPV4.Count == 0)
            {
                return "However no subnet are defined in them.";
            }

            // starts with 0.0.0.0
            bool zeroIPFound = false;
            foreach (var net in subnetsIPV4)
            {
                if (net.StartAddress.ToString() == "0.0.0.0")
                {
                    zeroIPFound = true;
                    break;
                }
            }

            if (!zeroIPFound)
            {
                return "However certain IP like 0.0.0.0 remain uncovered by any rules.";
            }
            var localNets = new List<Subnet>{
                new Subnet(IPAddress.Parse("10.0.0.0"), 8),
                new Subnet(IPAddress.Parse("172.16.0.0"), 12),
                new Subnet(IPAddress.Parse("192.168.0.0"), 16),
            };

            // look at the next IP of all subnets
            foreach (var net in subnetsIPV4)
            {
                try
                {
                    var nextIP = GetNextIPAddress(net.EndAddress);
                    if (IPAddress.IsLoopback(nextIP))
                        continue;
                    //  if covered by another range => ok
                    bool thisIsOk = false;
                    foreach (var net2 in subnetsIPV4)
                    {
                        if (net2.MatchIp(nextIP))
                        {
                            thisIsOk = true;
                            break;
                        }
                    }
                    if (thisIsOk)
                        continue;

                    //  if local network => ok
                    foreach (var net2 in localNets)
                    {
                        if (net2.MatchIp(nextIP))
                        {
                            thisIsOk = true;
                            break;
                        }
                    }
                    if (thisIsOk)
                        continue;

                    //  else, not covered
                    return "However certain IP like " + nextIP + " remain uncovered by any rules.";
                }
                catch (InvalidOperationException)
                {
                    //  if end of IP => ok                
                    continue;
                }
            }
            // ensure also that the next IP of local networks are covered
            foreach (var net in localNets)
            {
                var nextIP = GetNextIPAddress(net.EndAddress);
                bool thisIsOk = false;
                foreach (var net2 in subnetsIPV4)
                {
                    if (net2.MatchIp(nextIP))
                    {
                        thisIsOk = true;
                        break;

                    }
                }
                if (thisIsOk)
                    continue;

                //  else, not covered
                return "However certain IP like " + nextIP + " (the next IP after " + net + ") remain uncovered by any rules.";
            }
            return null;
        }

        IPAddress GetNextIPAddress(IPAddress existingAddress)
        {
            // Convert the existing IP address to a byte array
            byte[] existingBytes = existingAddress.GetAddressBytes();

            // Increment the last 64 bits (the host portion)
            for (int i = existingBytes.Length - 1; i >= 0; i--)
            {
                existingBytes[i]++;
                if (existingBytes[i] != 0) break; // No overflow
                if (i == 0) throw new InvalidOperationException(); // Overflow occurred
            }

            // Create the next IP address
            IPAddress nextIpAddress = new IPAddress(existingBytes);
            return nextIpAddress;
        }

    }
}
