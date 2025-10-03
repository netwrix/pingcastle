//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Healthcheck;
using PingCastle.UserInterface;
using System;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace PingCastle.Data
{
    public class PingCastleReportHelper<T> where T : IPingCastleReport
    {
        public static PingCastleReportCollection<T> LoadXmls(string Xmls, DateTime maxfiltervalue)
        {
            IUserInterface ui = UserInterfaceFactory.GetUserInterface();

            var output = new PingCastleReportCollection<T>();
            int files = 0;
            foreach (string filename in Directory.GetFiles(Xmls, PingCastleFactory.GetFilePatternForLoad<T>(), SearchOption.AllDirectories))
            {
                try
                {
                    files++;
                    T data = DataHelper<T>.LoadXml(filename);
                    // taking the more recent report
                    if (data.GenerationDate > maxfiltervalue)
                    {
                        Trace.WriteLine("File " + filename + " ignored because generation date " + data.GenerationDate.ToString("u") + " is after the consolidation date " + maxfiltervalue.ToString("u"));
                        continue;
                    }
                    output.Add(data);

                }
                catch (Exception ex)
                {
                    ui.DisplayError("Unable to load the file " + filename + " (" + ex.Message + ")");
                    Trace.WriteLine("Unable to load the file " + filename + " (" + ex.Message + ")");
                    Trace.WriteLine(ex.StackTrace);
                }
            }
            ui.DisplayMessage("Reports loaded: " + output.Count + " - on a total of " + files + " valid files");
            output.EnrichInformation();
            return output;
        }

        public static PingCastleReportHistoryCollection<T> LoadHistory(string Xmls, DateTime maxfiltervalue)
        {
            IUserInterface ui = UserInterfaceFactory.GetUserInterface();

            var output = new PingCastleReportHistoryCollection<T>();
            int files = 0;
            foreach (string filename in Directory.GetFiles(Xmls, "*ad_hc_*.xml", SearchOption.AllDirectories))
            {
                try
                {
                    files++;
                    var data = DataHelper<T>.LoadXml(filename);
                    // taking the more recent report
                    if (data.GenerationDate > maxfiltervalue)
                    {
                        Trace.WriteLine("File " + filename + " ignored because generation date " + data.GenerationDate.ToString("u") + " is after the consolidation date " + maxfiltervalue.ToString("u"));
                        continue;
                    }
                    output.Add(data);

                }
                catch (Exception ex)
                {
                    ui.DisplayError("Unable to load the file " + filename + " (" + ex.Message + ")");
                    Trace.WriteLine("Unable to load the file " + filename + " (" + ex.Message + ")");
                    Trace.WriteLine(ex.StackTrace);
                }
            }
            ui.DisplayMessage("Reports loaded: " + output.Count + " - on a total of " + files + " valid files");
            return output;
        }

        public static PingCastleReportCollection<HealthcheckData> TransformReportsToDemo(PingCastleReportCollection<HealthcheckData> consolidation)
        {
            string rotKey = GenerateRandomRotKey();

            var output = new PingCastleReportCollection<HealthcheckData>();
            foreach (HealthcheckData data in consolidation)
            {
                HealthcheckData demoreport = TransformReportToDemo(rotKey, data);
                output.Add(demoreport);
            }
            return output;
        }

        public static HealthcheckData TransformReportToDemo(string rotKey, HealthcheckData healthcheckData)
        {
            healthcheckData.DomainFQDN = TransformFQDNToDemo(rotKey, healthcheckData.DomainFQDN);
            healthcheckData.ForestFQDN = TransformFQDNToDemo(rotKey, healthcheckData.ForestFQDN);
            healthcheckData.NetBIOSName = TransformFQDNToDemo(rotKey, healthcheckData.NetBIOSName);
            if (healthcheckData.Trusts != null)
            {
                foreach (HealthCheckTrustData trust in healthcheckData.Trusts)
                {
                    trust.TrustPartner = TransformFQDNToDemo(rotKey, trust.TrustPartner);
                    if (trust.KnownDomains != null)
                    {
                        foreach (var di in trust.KnownDomains)
                        {
                            di.DnsName = TransformFQDNToDemo(rotKey, di.DnsName);
                            di.ForestName = TransformFQDNToDemo(rotKey, di.ForestName);
                            if (!String.IsNullOrEmpty(di.NetbiosName))
                                di.NetbiosName = TransformFQDNToDemo(rotKey, di.NetbiosName.ToLowerInvariant());
                        }
                    }
                }
            }
            if (healthcheckData.ReachableDomains != null)
            {
                foreach (var di in healthcheckData.ReachableDomains)
                {
                    if (di.DnsName.Equals(di.NetbiosName, StringComparison.InvariantCultureIgnoreCase))
                    {
                        di.NetbiosName = TransformFQDNToDemo(rotKey, di.NetbiosName.ToLowerInvariant());
                        di.DnsName = di.NetbiosName;
                    }
                    else
                    {
                        di.NetbiosName = TransformFQDNToDemo(rotKey, di.NetbiosName.ToLowerInvariant());
                        di.DnsName = TransformFQDNToDemo(rotKey, di.DnsName);
                    }
                    di.ForestName = TransformFQDNToDemo(rotKey, di.ForestName);
                }
            }
            return healthcheckData;
        }

        public static string TransformFQDNToDemo(string rotKey, string source)
        {
            if (String.IsNullOrEmpty(source))
                return null;
            StringBuilder sb = new StringBuilder(source.Length);
            source = source.ToLowerInvariant();
            for (int i = 0; i < source.Length; i++)
            {
                char c = source[i];
                if (c >= 97 && c <= 122)
                {
                    int j = c + rotKey[source.Length - 1 - i] - 97;
                    if (j > 122) j -= 26;
                    sb.Append((char)j);
                }
                else
                {
                    sb.Append(c);
                }
            }
            return sb.ToString();
        }

        public static string TransformNameToDemo(string rotKey, string source)
        {
            if (String.IsNullOrEmpty(source))
                return null;
            StringBuilder sb = new StringBuilder(source.Length);
            source = source.ToLowerInvariant();
            for (int i = 0; i < source.Length; i++)
            {
                char c = source[i];
                if (c >= 97 && c <= 122)
                {
                    int j = c + rotKey[i] - 97;
                    if (j > 122) j -= 26;
                    sb.Append((char)j);
                }
                else
                {
                    sb.Append(c);
                }
            }
            return sb.ToString();
        }

        public static string GenerateRandomRotKey()
        {
            string refstring = "abcdefghijklmnopqrstuvwxyz";
            var randomString = new StringBuilder();
            var random = new Random();
            for (int i = 0; i < 100; i++)
                randomString.Append(refstring[random.Next(refstring.Length)]);
            return randomString.ToString();
        }

    }
}
