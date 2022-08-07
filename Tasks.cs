//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Data;
using PingCastle.Exports;
using PingCastle.Healthcheck;
using PingCastle.misc;
using PingCastle.Report;
using PingCastle.Rules;
using PingCastle.Scanners;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Mail;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using TinyJson;

namespace PingCastle
{
    public class Tasks
    {
        public ADHealthCheckingLicense License { get; set; }
        public string Server = null;
        public int Port = 0;
        public NetworkCredential Credential = null;
        public List<string> NodesToInvestigate = new List<string>();
        public string FileOrDirectory = null;
        public PingCastleReportDataExportLevel ExportLevel = PingCastleReportDataExportLevel.Normal;
        public string sendXmlTo;
        public string sendHtmlTo;
        public string sendAllTo;
        public string sharepointdirectory;
        public string sharepointuser;
        public string sharepointpassword;
        public string CenterDomainForSimpliedGraph = null;
        public bool ExploreTerminalDomains;
        public bool ExploreForestTrust;
        public List<string> DomainToNotExplore;
        public bool EncryptReport = false;
        public bool InteractiveMode = false;
        public string mailNotification;
        public string smtpLogin;
        public string smtpPassword;
        public DateTime FilterReportDate = DateTime.MaxValue;
        public bool smtpTls;
        public Type Scanner;
        public Type Export;
        public string apiEndpoint;
        public string apiKey;
        public bool AnalyzeReachableDomains;
        public string botPipe;

        Dictionary<string, string> xmlreports = new Dictionary<string, string>();
        Dictionary<string, string> htmlreports = new Dictionary<string, string>();

        public bool GenerateKeyTask()
        {
            return StartTask("Generate Key",
                    () =>
                    {
                        HealthCheckEncryption.GenerateRSAKey();
                    });
        }

        public bool ScannerTask()
        {
            return StartTask("Scanner",
                    () =>
                    {
                        PropertyInfo pi = Scanner.GetProperty("Name");
                        IScanner scanner = PingCastleFactory.LoadScanner(Scanner);
                        string name = pi.GetValue(scanner, null) as string;
                        DisplayAdvancement("Running scanner " + name);
                        scanner.Initialize(Server, Port, Credential);
                        if (scanner as ScannerBase != null)
                            ((ScannerBase)scanner).FileOrDirectory = FileOrDirectory;
                        string file = "ad_scanner_" + name + "_" + Server + ".txt";
                        scanner.Export(file);
                        DisplayAdvancement("Results saved to " + new FileInfo(file).FullName);
                    }
                );
        }

        public bool CartoTask(bool PerformHealthCheckGenerateDemoReports)
        {
            List<HealthcheckAnalyzer.ReachableDomainInfo> domains = null;
            StartTask("Exploration",
                () =>
                {
                    HealthcheckAnalyzer hcroot = new HealthcheckAnalyzer();
                    hcroot.limitHoneyPot = string.IsNullOrEmpty(License.Edition);
                    domains = hcroot.GetAllReachableDomains(Port, Credential);
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("List of domains that will be queried");
                    Console.ResetColor();
                    foreach (var domain in domains)
                    {
                        Console.WriteLine(domain.domain);
                    }
                });
            var consolidation = new PingCastleReportCollection<HealthcheckData>();
            StartTask("Examining all domains in parallele (this can take a few minutes)",
            () =>
            {
                BlockingQueue<string> queue = new BlockingQueue<string>(30);
                int numberOfThread = 100;
                Thread[] threads = new Thread[numberOfThread];
                try
                {
                    ThreadStart threadFunction = () =>
                    {
                        for (; ; )
                        {
                            string domain = null;
                            if (!queue.Dequeue(out domain)) break;
                            try
                            {
                                Console.WriteLine("[" + DateTime.Now.ToLongTimeString() + "] " + "Starting the analysis of " + domain);
                                HealthcheckAnalyzer hc = new HealthcheckAnalyzer();
                                hc.limitHoneyPot = string.IsNullOrEmpty(License.Edition);

                                var data = hc.GenerateCartoReport(domain, Port, Credential, AnalyzeReachableDomains);
                                consolidation.Add(data);
                                Console.WriteLine("[" + DateTime.Now.ToLongTimeString() + "] " + "Analysis of " + domain + " completed with success");
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine("[" + DateTime.Now.ToLongTimeString() + "] " + "Analysis of " + domain + " failed");
                                Trace.WriteLine("Exception while analysing domain " + domain + " : " + ex.Message);
                                Trace.WriteLine(ex.StackTrace);
                            }
                        }
                    };
                    // Consumers
                    for (int i = 0; i < numberOfThread; i++)
                    {
                        threads[i] = new Thread(threadFunction);
                        threads[i].Start();
                    }
                    foreach (var domain in domains)
                    {
                        queue.Enqueue(domain.domain);
                    }
                    queue.Quit();
                    Trace.WriteLine("examining domains file completed. Waiting for worker thread to complete");
                    for (int i = 0; i < numberOfThread; i++)
                    {
                        threads[i].Join();
                    }
                    Trace.WriteLine("Done examining domains");
                }
                catch (Exception ex)
                {
                    Trace.WriteLine("Exception while analysing domain in carto: " + ex.Message);
                    Trace.WriteLine(ex.StackTrace);
                }
                finally
                {
                    queue.Quit();
                    for (int i = 0; i < numberOfThread; i++)
                    {
                        if (threads[i] != null)
                            if (threads[i].ThreadState == System.Threading.ThreadState.Running)
                                threads[i].Abort();
                    }
                }
            });
            if (PerformHealthCheckGenerateDemoReports)
            {
                Console.WriteLine("Performing demo report transformation");
                Trace.WriteLine("Performing demo report transformation");
                consolidation = PingCastleReportHelper<HealthcheckData>.TransformReportsToDemo(consolidation);
            }
            if (!StartTask("Healthcheck consolidation",
                () =>
                {
                    consolidation.EnrichInformation();
                    ReportHealthCheckMapBuilder nodeAnalyzer = new ReportHealthCheckMapBuilder(consolidation, License);
                    nodeAnalyzer.Log = Console.WriteLine;
                    nodeAnalyzer.CenterDomainForSimpliedGraph = CenterDomainForSimpliedGraph;
                    nodeAnalyzer.GenerateReportFile("ad_carto_full_node_map.html");
                    nodeAnalyzer.FullNodeMap = false;
                    nodeAnalyzer.CenterDomainForSimpliedGraph = CenterDomainForSimpliedGraph;
                    nodeAnalyzer.GenerateReportFile("ad_carto_simple_node_map.html");
                }
            )) return false;
            return true;
        }

        public bool AnalysisTask<T>() where T : IPingCastleReport
        {
            if (!string.IsNullOrEmpty(apiEndpoint) && !string.IsNullOrEmpty(apiKey))
            {
                var ret = RetrieveSettingsViaAPI();
                if (!ret)
                    return false;
            }
            string[] servers = Server.Split(',');
            foreach (string server in servers)
            {
                AnalysisTask<T>(server);
            }
            return true;
        }

        public bool CompleteTasks()
        {
            if (xmlreports.Count == 0 && htmlreports.Count == 0)
                return true;
            if (!String.IsNullOrEmpty(sendXmlTo))
                SendEmail(sendXmlTo, true, false);
            if (!String.IsNullOrEmpty(sendHtmlTo))
                SendEmail(sendHtmlTo, false, true);
            if (!String.IsNullOrEmpty(sendAllTo))
                SendEmail(sendAllTo, true, true);
            if (!String.IsNullOrEmpty(sharepointdirectory))
            {
                foreach (string domain in xmlreports.Keys)
                {
                    UploadToWebsite("ad_hc_" + domain + ".xml", xmlreports[domain]);
                }
            }
            if (!String.IsNullOrEmpty(apiKey) && !String.IsNullOrEmpty(apiEndpoint))
                SendViaAPI(xmlreports);
            return true;
        }

        public bool GenerateFakeReport()
        {
            return StartTask("Generate fake reports",
                    () =>
                    {
                        var fakegenerator = new FakeHealthCheckDataGenerator();
                        var hcconso = fakegenerator.GenerateData();

                        foreach (var pingCastleReport in hcconso)
                        {
                            var enduserReportGenerator = new ReportHealthCheckSingle();
                            enduserReportGenerator.GenerateReportFile(pingCastleReport, License, pingCastleReport.GetHumanReadableFileName());
                            DisplayAdvancement("Export level is " + ExportLevel);
                            if (ExportLevel != PingCastleReportDataExportLevel.Full)
                            {
                                DisplayAdvancement("Personal data will NOT be included in the .xml file (add --level Full to add it)");
                            }
                            pingCastleReport.SetExportLevel(ExportLevel);
                            DataHelper<HealthcheckData>.SaveAsXml(pingCastleReport, pingCastleReport.GetMachineReadableFileName(), EncryptReport);

                        }

                        var reportConso = new ReportHealthCheckConsolidation();
                        reportConso.GenerateReportFile(hcconso, License, "ad_hc_summary.html");
                        ReportHealthCheckMapBuilder nodeAnalyzer = new ReportHealthCheckMapBuilder(hcconso, License);
                        nodeAnalyzer.Log = Console.WriteLine;
                        nodeAnalyzer.GenerateReportFile("ad_hc_summary_full_node_map.html");
                        nodeAnalyzer.FullNodeMap = false;
                        nodeAnalyzer.CenterDomainForSimpliedGraph = CenterDomainForSimpliedGraph;
                        nodeAnalyzer.GenerateReportFile("ad_hc_summary_simple_node_map.html");
                        var mapReport = new ReportNetworkMap();
                        mapReport.GenerateReportFile(hcconso, License, "ad_hc_hilbert_map.html");
                    }
                );
        }

        public bool AnalysisCheckTask<T>(string server)
        {
            return true;
        }

        public bool AnalysisTask<T>(string server) where T : IPingCastleReport
        {
            Trace.WriteLine("Working on " + server);
            if (server == "*" && InteractiveMode)
            {
                Trace.WriteLine("Setting reachable domains to on because interactive + server = *");
                AnalyzeReachableDomains = true;
            }
            if (server.Contains("*"))
            {
                List<string> domains = GetListOfDomainToExploreFromGenericName(server);
                int i = 1;

                foreach (var domain in domains)
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("");
                    string display = "Starting the report for " + domain + " (" + i++ + "/" + domains.Count + ")";
                    Console.WriteLine(display);
                    Console.WriteLine(new String('=', display.Length));
                    Console.ResetColor();
                    PerformTheAnalysis(domain);
                }

            }
            else
            {
                var data = PerformTheAnalysis(server);
                var hcData = data as HealthcheckData;
                // do additional exploration based on trust results ?
                Trace.WriteLine("do additional exploration based on trust results ?");
                if (hcData != null && (ExploreTerminalDomains || ExploreForestTrust))
                {
                    Trace.WriteLine("ExploreTerminalDomains is " + ExploreTerminalDomains);
                    Trace.WriteLine("ExploreForestTrust is " + ExploreForestTrust);
                    if (hcData.Trusts != null)
                    {
                        List<string> domainToExamine = new List<string>();
                        foreach (var trust in hcData.Trusts)
                        {
                            Trace.WriteLine("Examining " + trust.TrustPartner + " for additional exploration");
                            string attributes = TrustAnalyzer.GetTrustAttribute(trust.TrustAttributes);
                            string direction = TrustAnalyzer.GetTrustDirection(trust.TrustDirection);
                            if (direction.Contains("Inbound") || direction.Contains("Disabled"))
                                continue;
                            if (attributes.Contains("Intra-Forest"))
                                continue;
                            // explore forest trust only if explore forest trust is set
                            if (attributes.Contains("Forest Trust"))
                            {
                                if (ExploreForestTrust)
                                {
                                    if (!ShouldTheDomainBeNotExplored(trust.TrustPartner))
                                        domainToExamine.Add(trust.TrustPartner);
                                    else
                                        Trace.WriteLine("Domain " + trust.TrustPartner + " not to explore (direct domain)");
                                    if (trust.KnownDomains != null)
                                    {
                                        foreach (var di in trust.KnownDomains)
                                        {
                                            if (!ShouldTheDomainBeNotExplored(di.DnsName))
                                                domainToExamine.Add(di.DnsName);
                                            Trace.WriteLine("Domain " + di.DnsName + " not to explore (known domain)");
                                        }
                                    }
                                }
                            }
                            else
                            {
                                if (ExploreTerminalDomains)
                                {
                                    if (!ShouldTheDomainBeNotExplored(trust.TrustPartner))
                                        domainToExamine.Add(trust.TrustPartner);
                                    else
                                        Trace.WriteLine("Domain " + trust.TrustPartner + "not to explore (terminal domain)");
                                }
                            }
                        }
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine("List of domains that will be queried");
                        Trace.WriteLine("List of domains that will be queried");
                        Console.ResetColor();
                        foreach (var domain in domainToExamine)
                        {
                            Console.WriteLine(domain);
                            Trace.WriteLine(domain);
                        }
                        Trace.WriteLine("End selection");
                        foreach (string domain in domainToExamine)
                        {
                            PerformTheAnalysis(domain);
                        }
                    }
                }
                Trace.WriteLine("done additional exploration");
                return hcData != null;
            }
            return true;
        }

        private List<string> GetListOfDomainToExploreFromGenericName(string server)
        {
            List<string> domains = new List<string>();
            StartTask("Exploration",
                () =>
                {
                    HealthcheckAnalyzer hcroot = new HealthcheckAnalyzer();
                    hcroot.limitHoneyPot = string.IsNullOrEmpty(License.Edition);
                    var reachableDomains = hcroot.GetAllReachableDomains(Port, Credential);
                    List<HealthcheckAnalyzer.ReachableDomainInfo> domainsfiltered = new List<HealthcheckAnalyzer.ReachableDomainInfo>();
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("List of domains that will be queried");
                    Console.ResetColor();
                    foreach (var reachableDomain in reachableDomains)
                    {
                        if (compareStringWithWildcard(server, reachableDomain.domain) && !ShouldTheDomainBeNotExplored(reachableDomain.domain))
                        {
                            domains.Add(reachableDomain.domain);
                            Console.WriteLine(reachableDomain.domain);
                        }
                    }
                });
            return domains;
        }

        public static bool compareStringWithWildcard(string stringWithWildcard, string toCompare)
        {
            string regex = "^" + Regex.Escape(stringWithWildcard)
                              .Replace(@"\*", ".*")
                              .Replace(@"\?", ".")
                       + "$";
            return Regex.Match(toCompare, regex, RegexOptions.IgnoreCase).Success;
        }

        bool ShouldTheDomainBeNotExplored(string domainToCheck)
        {
            if (DomainToNotExplore == null)
                return false;
            foreach (string domain in DomainToNotExplore)
            {
                if (domainToCheck.Equals(domain, StringComparison.InvariantCultureIgnoreCase))
                {
                    Trace.WriteLine("Domain " + domainToCheck + " is filtered");
                    return true;
                }
            }
            return false;
        }

        HealthcheckData PerformTheAnalysis(string server)
        {
            HealthcheckData pingCastleReport = null;
            bool status = StartTask("Perform analysis for " + server,
                () =>
                {
                    var analyzer = new HealthcheckAnalyzer();
                    analyzer.limitHoneyPot = string.IsNullOrEmpty(License.Edition);
                    pingCastleReport = analyzer.PerformAnalyze(new PingCastleAnalyzerParameters()
                    {
                        Server = server,
                        Port = Port,
                        Credential = Credential,
                        PerformExtendedTrustDiscovery = AnalyzeReachableDomains,
                        AdditionalNamesForDelegationAnalysis = NodesToInvestigate,
                    });
                    string domain = pingCastleReport.Domain.DomainName;
                    DisplayAdvancement("Generating html report");
                    var enduserReportGenerator = new ReportHealthCheckSingle();
                    htmlreports[domain] = enduserReportGenerator.GenerateReportFile(pingCastleReport, License, pingCastleReport.GetHumanReadableFileName());
                    DisplayAdvancement("Generating xml file for consolidation report" + (EncryptReport ? " (encrypted)" : ""));
                    DisplayAdvancement("Export level is " + ExportLevel);
                    if (ExportLevel != PingCastleReportDataExportLevel.Full)
                    {
                        DisplayAdvancement("Personal data will NOT be included in the .xml file (add --level Full to add it)");
                    }
                    pingCastleReport.SetExportLevel(ExportLevel);
                    xmlreports[domain] = DataHelper<HealthcheckData>.SaveAsXml(pingCastleReport, pingCastleReport.GetMachineReadableFileName(), EncryptReport);
                    DisplayAdvancement("Done");
                });
            return pingCastleReport;
        }

        public bool ConsolidationTask<T>() where T : IPingCastleReport
        {
            return StartTask("PingCastle report consolidation (" + typeof(T).Name + ")",
                    () =>
                    {
                        if (String.IsNullOrEmpty(FileOrDirectory))
                        {
                            FileOrDirectory = Directory.GetCurrentDirectory();
                        }
                        if (!Directory.Exists(FileOrDirectory))
                        {
                            WriteInRed("The directory " + FileOrDirectory + " doesn't exist");
                            return;
                        }
                        var consolidation = PingCastleReportHelper<T>.LoadXmls(FileOrDirectory, FilterReportDate);
                        if (consolidation.Count == 0)
                        {
                            WriteInRed("No report has been found. Please generate one with PingCastle and try again. The task will stop.");
                            return;
                        }
                        if (typeof(T) == typeof(HealthcheckData))
                        {
                            var hcconso = consolidation as PingCastleReportCollection<HealthcheckData>;
                            var report = new ReportHealthCheckConsolidation();
                            report.GenerateReportFile(hcconso, License, "ad_hc_summary.html");
                            ReportHealthCheckMapBuilder nodeAnalyzer = new ReportHealthCheckMapBuilder(hcconso, License);
                            nodeAnalyzer.Log = Console.WriteLine;
                            nodeAnalyzer.GenerateReportFile("ad_hc_summary_full_node_map.html");
                            nodeAnalyzer.FullNodeMap = false;
                            nodeAnalyzer.CenterDomainForSimpliedGraph = CenterDomainForSimpliedGraph;
                            nodeAnalyzer.GenerateReportFile("ad_hc_summary_simple_node_map.html");
                            var mapReport = new ReportNetworkMap();
                            mapReport.GenerateReportFile(hcconso, License, "ad_hc_hilbert_map.html");
                        }
                    }
                );
        }

        public bool HealthCheckRulesTask()
        {
            return StartTask("PingCastle Health Check rules",
                    () =>
                    {
                        if (String.IsNullOrEmpty(FileOrDirectory))
                        {
                            FileOrDirectory = Directory.GetCurrentDirectory();
                        }
                        if (!Directory.Exists(FileOrDirectory))
                        {
                            WriteInRed("The directory " + FileOrDirectory + " doesn't exist");
                            return;
                        }
                        var rulesBuilder = new ReportHealthCheckRules();
                        rulesBuilder.GenerateReportFile("ad_hc_rules_list.html");
                    }
                );
        }


        public bool RegenerateHtmlTask()
        {
            return StartTask("Regenerate html report",
                    () =>
                    {
                        if (!File.Exists(FileOrDirectory))
                        {
                            WriteInRed("The file " + FileOrDirectory + " doesn't exist");
                            return;
                        }
                        var fi = new FileInfo(FileOrDirectory);
                        var healthcheckData = DataHelper<HealthcheckData>.LoadXml(FileOrDirectory);
                        var endUserReportGenerator = new ReportHealthCheckSingle();
                        endUserReportGenerator.GenerateReportFile(healthcheckData, License, healthcheckData.GetHumanReadableFileName());
                    }
                );
        }

        public bool ReloadXmlReport()
        {
            return StartTask("Reload report",
                    () =>
                    {
                        if (!File.Exists(FileOrDirectory))
                        {
                            WriteInRed("The file " + FileOrDirectory + " doesn't exist");
                            return;
                        }
                        string newfile = FileOrDirectory.Replace(".xml", "_reloaded.xml");
                        string xml = null;
                        string domainFQDN = null;
                        var fi = new FileInfo(FileOrDirectory);
                        if (fi.Name.StartsWith("ad_hc_"))
                        {
                            HealthcheckData healthcheckData = DataHelper<HealthcheckData>.LoadXml(FileOrDirectory);
                            domainFQDN = healthcheckData.DomainFQDN;
                            DisplayAdvancement("Regenerating xml " + (EncryptReport ? " (encrypted)" : ""));
                            healthcheckData.Level = ExportLevel;
                            xml = DataHelper<HealthcheckData>.SaveAsXml(healthcheckData, newfile, EncryptReport);
                        }
                        else
                        {
                            DisplayAdvancement("file ignored because it does not start with ad_hc_");
                        }
                        if (!String.IsNullOrEmpty(apiKey) && !String.IsNullOrEmpty(apiEndpoint))
                            SendViaAPI(new Dictionary<string, string>() { { fi.Name, xml } });
                        if (!String.IsNullOrEmpty(sharepointdirectory))
                            UploadToWebsite(newfile, xml);
                        if (!String.IsNullOrEmpty(sendXmlTo))
                            SendEmail(sendXmlTo, new List<string> { domainFQDN },
                                new List<Attachment> { Attachment.CreateAttachmentFromString(xml, newfile) });
                        if (!String.IsNullOrEmpty(sendHtmlTo))
                            WriteInRed("Html report ignored when xml file used as input");
                        if (!String.IsNullOrEmpty(sendAllTo))
                        {
                            WriteInRed("Html report ignored when xml file used as input");
                            SendEmail(sendAllTo, new List<string> { domainFQDN },
                                new List<Attachment> { Attachment.CreateAttachmentFromString(xml, newfile) });
                        }
                    }
                );
        }

        public bool UploadAllReportInCurrentDirectory()
        {
            return StartTask("Upload report",
                () =>
                {
                    if (String.IsNullOrEmpty(apiKey) || String.IsNullOrEmpty(apiEndpoint))
                        throw new PingCastleException("API end point not available");
                    var files = new List<string>(Directory.GetFiles(Directory.GetCurrentDirectory(), "*ad_*.xml", SearchOption.AllDirectories));
                    files.Sort();
                    DisplayAdvancement(files.Count + " files to import (only ad_*.xml files are uploaded)");
                    var reports = new List<KeyValuePair<string, string>>();
                    int i = 1;
                    foreach (string file in files)
                    {
                        if (i % 50 == 0)
                        {
                            DisplayAdvancement("Uploading file up to #" + i);
                            SendViaAPI(reports);
                            reports.Clear();
                        }
                        string filename = Path.GetFileNameWithoutExtension(file);
                        reports.Add(new KeyValuePair<string, string>(filename, File.ReadAllText(file)));
                        i++;
                    }
                    if (reports.Count > 0)
                        SendViaAPI(reports);
                }
            );
        }

        public bool GenerateDemoReportTask()
        {
            return StartTask("Generating demo reports",
                    () =>
                    {
                        if (String.IsNullOrEmpty(FileOrDirectory))
                        {
                            FileOrDirectory = Directory.GetCurrentDirectory();
                        }
                        if (!Directory.Exists(FileOrDirectory))
                        {
                            WriteInRed("The directory " + FileOrDirectory + " doesn't exist");
                            return;
                        }
                        string path = Path.Combine(FileOrDirectory, "demo");
                        if (!Directory.Exists(path))
                        {
                            Directory.CreateDirectory(path);
                        }
                        var consolidation = PingCastleReportHelper<HealthcheckData>.LoadXmls(FileOrDirectory, FilterReportDate);
                        if (consolidation.Count == 0)
                        {
                            WriteInRed("No report has been found. Please generate one with PingCastle and the Health Check mode. The program will stop.");
                            return;
                        }
                        consolidation = PingCastleReportHelper<HealthcheckData>.TransformReportsToDemo(consolidation);
                        foreach (HealthcheckData data in consolidation)
                        {
                            string domain = data.DomainFQDN;
                            var endUserReportGenerator = new ReportHealthCheckSingle();
                            string html = endUserReportGenerator.GenerateReportFile(data, License, Path.Combine(path, data.GetHumanReadableFileName()));
                            data.SetExportLevel(ExportLevel);
                            string xml = DataHelper<HealthcheckData>.SaveAsXml(data, Path.Combine(path, data.GetMachineReadableFileName()), EncryptReport);
                        }

                    }
                );
        }

        // return JWT token
        void SendViaAPIGetJwtToken(WebClient client)
        {
            ServicePointManager.Expect100Continue = false;
            client.UseDefaultCredentials = true;
            client.Proxy = WebRequest.DefaultWebProxy;
            if (client.Proxy == null)
            {
                Trace.WriteLine("No proxy");
            }
            else
            {
                Trace.WriteLine("with proxy");
                Trace.WriteLine("Using proxy:" + client.Proxy.GetProxy(new Uri(apiEndpoint)));
                Trace.WriteLine("Is bypassed:" + client.Proxy.IsBypassed(new Uri(apiEndpoint)));
            }
            Version version = Assembly.GetExecutingAssembly().GetName().Version;
            client.Headers.Add(HttpRequestHeader.ContentType, "application/json");
            client.Headers.Add(HttpRequestHeader.UserAgent, "PingCastle " + version.ToString(4));
            //client.Headers.Add("Authorization", token);
            string token;
            byte[] answer = null;
            try
            {
                //https://docs.microsoft.com/en-us/dotnet/api/system.net.securityprotocoltype?view=netcore-3.1
                // try enable TLS1.1
                try
                {
                    System.Net.ServicePointManager.SecurityProtocol = (System.Net.SecurityProtocolType)(768 | (int)System.Net.ServicePointManager.SecurityProtocol);
                }
                catch
                {
                }
                // try enable TLS1.2
                try
                {
                    System.Net.ServicePointManager.SecurityProtocol = (System.Net.SecurityProtocolType)(3072 | (int)System.Net.ServicePointManager.SecurityProtocol);
                }
                catch
                {
                }
                // try enable TLS1.3
                try
                {
                    System.Net.ServicePointManager.SecurityProtocol = (System.Net.SecurityProtocolType)(12288 | (int)System.Net.ServicePointManager.SecurityProtocol);
                }
                catch
                {
                }
                string location = Dns.GetHostEntry(Environment.MachineName).HostName;
                Trace.WriteLine("location: " + location);
                Trace.WriteLine("apikey: " + apiKey);
                byte[] data = Encoding.Default.GetBytes("{\"apikey\": \"" + ReportHelper.EscapeJsonString(apiKey) + "\",\"location\": \"" + ReportHelper.EscapeJsonString(location) + "\"}");
                answer = client.UploadData(apiEndpoint + "api/Agent/Login", "POST", data);
                token = Encoding.Default.GetString(answer);
                Trace.WriteLine("token: " + token);
                client.Headers.Add(HttpRequestHeader.Authorization, token);
            }
            catch (WebException ex)
            {
                if (ex.Status == WebExceptionStatus.SecureChannelFailure)
                {
                    WriteInRed("If you require TLS 1.2 or 1.3 for API, be sure you have installed the Windows patch to support TLS 1.2 or 1.3");
                    WriteInRed("See kb3140245 and KB4019276 for TLS 1.2");
                    WriteInRed("Be sure also that .NET has been patched to handle the TLS version");
                }
                if (ex.Response != null)
                {
                    var responseStream = ex.Response.GetResponseStream();
                    if (responseStream != null)
                    {
                        using (var reader = new StreamReader(responseStream))
                        {
                            string responseText = reader.ReadToEnd();
                            throw new UnauthorizedAccessException(responseText);
                        }
                    }
                }
                throw new UnauthorizedAccessException(ex.Message);
            }
        }

        string SendViaAPIUploadOneReport(WebClient client, string filename, string xml)
        {
            byte[] answer = null;
            Version version = Assembly.GetExecutingAssembly().GetName().Version;
            client.Headers.Add(HttpRequestHeader.ContentType, "application/json");
            client.Headers.Add(HttpRequestHeader.UserAgent, "PingCastle " + version.ToString(4));
            try
            {
                Trace.WriteLine("using filename:" + filename);
                var request = "{\"xmlReport\": \"" + ReportHelper.EscapeJsonString(xml) + "\",\"filename\":\"" + ReportHelper.EscapeJsonString(filename) + "\"}";
                byte[] data = Encoding.ASCII.GetBytes(request);
                answer = client.UploadData(apiEndpoint + "api/Agent/SendReport", "POST", data);
                var o = Encoding.Default.GetString(answer);
                Trace.WriteLine("answer:" + o);
                return o;
            }
            catch (WebException ex)
            {
                Trace.WriteLine("Status: " + ex.Status);
                Trace.WriteLine("Message: " + ex.Message);
                if (ex.Response != null)
                {
                    var responseStream = ex.Response.GetResponseStream();
                    if (responseStream != null)
                    {
                        using (var reader = new StreamReader(responseStream))
                        {
                            string responseText = reader.ReadToEnd();
                            if (string.IsNullOrEmpty(responseText))
                                responseText = ex.Message;
                            throw new PingCastleException(responseText);
                        }
                    }
                }
                else
                {
                    Trace.WriteLine("WebException response null");
                }
                throw;
            }
        }

        public class CustomComputationRule
        {
            public string ComputationType { get; set; }
            public int Score { get; set; }
            public int Threshold { get; set; }
            public int Order { get; set; }
        }
        public class CustomRule
        {
            public string RiskID { get; set; }
            public int? MaturityLevel { get; set; }
            public List<CustomComputationRule> Computation { get; set; }
        }

        public class AgentSettings
        {
            public string License { get; set; }
            public string ExportLevel { get; set; }
            public List<CustomRule> CustomRules { get; set; }
        }

        private void ProcessSettings(WebClient client)
        {
            Version version = Assembly.GetExecutingAssembly().GetName().Version;
            client.Headers.Add(HttpRequestHeader.ContentType, "application/json");
            client.Headers.Add(HttpRequestHeader.UserAgent, "PingCastle " + version.ToString(4));
            try
            {
                string answer = client.DownloadString(apiEndpoint + "api/Agent/GetSettings");
                Trace.WriteLine("answer:" + answer);
                DisplayAdvancement("OK");

                // TinyJson is extracted from https://github.com/zanders3/json
                // MIT License
                var deserializedResult = JSONParser.FromJson<AgentSettings>(answer);

                // could also use this serializer, but starting .Net 4 only (not .net 3)
                //var serializer = new System.Web.Script.Serialization.JavaScriptSerializer();
                //var deserializedResult = serializer.Deserialize<AgentSettings>(answer);

                if (deserializedResult.License != null)
                {
                    try
                    {
                        var license = new ADHealthCheckingLicense(deserializedResult.License);
                        if (license.EndTime > DateTime.Now)
                            License = license;
                    }
                    catch (Exception ex)
                    {
                        Trace.WriteLine(ex.Message);
                    }
                }
                if (!string.IsNullOrEmpty(deserializedResult.ExportLevel))
                {
                    try
                    {
                        // enum parsed as string to avoid a problem is a newer version of the enum is sent over the wire
                        ExportLevel = (PingCastleReportDataExportLevel)Enum.Parse(typeof(PingCastleReportDataExportLevel), deserializedResult.ExportLevel);
                    }
                    catch (Exception)
                    {
                        Trace.WriteLine("Unable to parse the level [" + deserializedResult.ExportLevel + "] to one of the predefined value (" + String.Join(",", Enum.GetNames(typeof(PingCastleReportDataExportLevel))) + ")");
                    }
                }
                if (deserializedResult.CustomRules != null && deserializedResult.CustomRules.Count != 0)
                {
                    if (string.IsNullOrEmpty(License.Edition) || License.Edition == "Auditor")
                    {
                        Trace.WriteLine("Custom rules not allowed");
                    }
                    else
                    {
                        foreach (var rule in deserializedResult.CustomRules)
                        {
                            var hcrule = RuleSet<HealthcheckData>.GetRuleFromID(rule.RiskID);
                            if (hcrule == null)
                            {
                                Trace.WriteLine("Rule " + rule.RiskID + " ignored because not found");
                                continue;
                            }
                            if (rule.MaturityLevel != null)
                            {
                                hcrule.MaturityLevel = (int)rule.MaturityLevel;
                            }
                            if (rule.Computation != null && rule.Computation.Count > 0)
                            {
                                var computations = new List<RuleComputationAttribute>();
                                foreach (var c in rule.Computation)
                                {
                                    RuleComputationType type;
                                    try
                                    {
                                        // enum parsed as string to avoid a problem is a newer version of the enum is sent over the wire
                                        type = (RuleComputationType)Enum.Parse(typeof(RuleComputationType), c.ComputationType);
                                    }
                                    catch (Exception)
                                    {
                                        Trace.WriteLine("Unable to parse the RuleComputationType [" + c.ComputationType + "] to one of the predefined value (" + String.Join(",", Enum.GetNames(typeof(RuleComputationType))) + ")");
                                        computations.Clear();
                                        break;
                                    }
                                    computations.Add(new RuleComputationAttribute(type, c.Score, c.Threshold, c.Order));
                                }
                                if (computations.Count > 0)
                                {
                                    hcrule.RuleComputation.Clear();
                                    hcrule.RuleComputation.AddRange(computations);
                                }
                            }
                        }
                    }
                }
            }
            catch (WebException ex)
            {
                if (ex.Status == WebExceptionStatus.ProtocolError && ex.Response != null)
                {
                    var resp = (HttpWebResponse)ex.Response;
                    if (resp.StatusCode == HttpStatusCode.NotFound) // HTTP 404
                    {
                        Trace.WriteLine("GetSettings page not found");
                        DisplayAdvancement("Not found");
                        return;
                    }
                }
                Trace.WriteLine("Status: " + ex.Status);
                Trace.WriteLine("Message: " + ex.Message);
                if (ex.Response != null)
                {
                    var responseStream = ex.Response.GetResponseStream();
                    if (responseStream != null)
                    {
                        using (var reader = new StreamReader(responseStream))
                        {
                            string responseText = reader.ReadToEnd();
                            if (string.IsNullOrEmpty(responseText))
                                responseText = ex.Message;
                            throw new PingCastleException(responseText);
                        }
                    }
                }
                else
                {
                    Trace.WriteLine("WebException response null");
                }
                throw;
            }
        }

        void SendViaAPI(IEnumerable<KeyValuePair<string, string>> xmlreports)
        {
            StartTask("Send via API",
                    () =>
                    {
                        if (!apiEndpoint.EndsWith("/"))
                            apiEndpoint += "/";
                        Trace.WriteLine("apiendpoint: " + apiEndpoint);
                        using (WebClient client = new WebClient())
                        {
                            try
                            {
                                SendViaAPIGetJwtToken(client);
                                DisplayAdvancement("API Login OK");
                            }
                            catch (UnauthorizedAccessException ex)
                            {
                                WriteInRed("Login failed (" + ex.Message + ")");
                                return;
                            }
                            foreach (KeyValuePair<string, string> report in xmlreports)
                            {
                                try
                                {
                                    string answer = SendViaAPIUploadOneReport(client, report.Key, report.Value);
                                    DisplayAdvancement(report.Key + "-" + (String.IsNullOrEmpty(answer) ? "OK" : answer));
                                }
                                catch (Exception ex)
                                {
                                    Trace.WriteLine("Exception:");
                                    Trace.WriteLine(ex.GetType());
                                    Trace.WriteLine(ex.Message);
                                    Trace.WriteLine(ex.StackTrace);
                                    WriteInRed(report.Key);
                                    DisplayException(null, ex);
                                }
                            }
                        }
                    });
        }

        bool RetrieveSettingsViaAPI()
        {
            bool ret = true;
            StartTask("Retrieve Settings via API",
                    () =>
                    {
                        if (!apiEndpoint.EndsWith("/"))
                            apiEndpoint += "/";
                        Trace.WriteLine("apiendpoint: " + apiEndpoint);
                        using (WebClient client = new WebClient())
                        {
                            try
                            {
                                SendViaAPIGetJwtToken(client);
                                DisplayAdvancement("API Login OK");
                            }
                            catch (UnauthorizedAccessException ex)
                            {
                                WriteInRed("Login failed (" + ex.Message + ")");
                                ret = false;
                                return;
                            }
                            try
                            {
                                ProcessSettings(client);
                            }
                            catch (Exception ex)
                            {
                                Trace.WriteLine("Exception:");
                                Trace.WriteLine(ex.GetType());
                                Trace.WriteLine(ex.Message);
                                Trace.WriteLine(ex.StackTrace);
                                DisplayException(null, ex);
                            }
                        }
                    });
            return ret;
        }

        void SendEmail(string email, List<string> domains, List<Attachment> Files)
        {
            Version version = Assembly.GetExecutingAssembly().GetName().Version;
            var versionString = version.ToString(4);
#if DEBUG
            versionString += " Beta";
#endif
            string body = @"Hello,

This is the PingCastle program sending reports for:
- " + String.Join("\r\n- ", domains.ToArray());
            SendEmail(email, "[PingCastle][" + versionString + "] Reports for " + String.Join(",", domains.ToArray()), body, Files);
        }

        void SendEmail(string email, bool xml, bool html)
        {
            List<Attachment> Files = new List<Attachment>();
            List<string> domains = new List<string>();
            if (xml)
            {
                foreach (string domain in xmlreports.Keys)
                {
                    if (!domains.Contains(domain))
                        domains.Add(domain);
                    Files.Add(Attachment.CreateAttachmentFromString(xmlreports[domain], "ad_hc_" + domain + ".xml"));
                }
            }
            if (html)
            {
                foreach (string domain in htmlreports.Keys)
                {
                    if (!domains.Contains(domain))
                        domains.Add(domain);
                    Files.Add(Attachment.CreateAttachmentFromString(htmlreports[domain], "ad_hc_" + domain + ".html"));
                }
            }
            SendEmail(email, domains, Files);
        }

        void SendEmail(string recipient, string subject, string body, List<Attachment> attachments)
        {
            StartTask("Send email",
                    () =>
                    {
                        MailMessage message = new MailMessage();
                        foreach (Attachment attachment in attachments)
                        {
                            message.Attachments.Add(attachment);
                        }
                        message.Subject = subject;
                        message.Body = body;
                        message.To.Add(recipient);
                        if (!String.IsNullOrEmpty(mailNotification))
                        {
                            message.Headers.Add("Disposition-Notification-To", mailNotification);
                            message.Headers.Add("Return-Receipt-To", mailNotification);
                        }
                        SmtpClient client = new SmtpClient();
                        if (smtpTls)
                            client.EnableSsl = true;
                        else
                            client.EnableSsl = (client.Port == 587 || client.Port == 465);
                        if (!String.IsNullOrEmpty(smtpLogin) || !String.IsNullOrEmpty(smtpPassword))
                            client.Credentials = new NetworkCredential(smtpLogin, smtpPassword);
                        client.Send(message);
                    }
                    );
        }

        void UploadToWebsite(string filename, string filecontent)
        {
            StartTask("Upload to website",
                    () =>
                    {
                        WebClient client = new WebClient();
                        if (!String.IsNullOrEmpty(sharepointuser))
                            client.Credentials = new NetworkCredential(sharepointuser, sharepointpassword);
                        else
                            client.UseDefaultCredentials = true;
                        string url = sharepointdirectory + (sharepointdirectory.EndsWith("/") ? null : "/") + filename;
                        Trace.WriteLine("url: " + url);
                        client.UploadData(url, "PUT", Encoding.UTF8.GetBytes(filecontent));
                    }
            );
        }

        public bool BotTask()
        {
            return StartTask("Running Bot",
                    () =>
                    {
                        var bot = new PingCastle.Bot.Bot();
                        bot.Run(botPipe);
                    }
            );
        }

        public bool ExportTask()
        {
            return StartTask("Running Export",
                    () =>
                    {

                        PropertyInfo pi = Export.GetProperty("Name");
                        IExport export = PingCastleFactory.LoadExport(Export);
                        string name = pi.GetValue(export, null) as string;
                        DisplayAdvancement("Running export " + name);
                        export.Initialize(Server, Port, Credential);
                        string file = "ad_export_" + name + "_" + Server + ".txt";
                        export.Export(file);
                        DisplayAdvancement("Results saved to " + new FileInfo(file).FullName);
                    }
            );
        }

        // function used to encapsulate a task and to fail gracefully with an error message
        // return true is success; false in cas of failure
        delegate void TaskDelegate();
        private bool StartTask(string taskname, TaskDelegate taskdelegate)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("Starting the task: " + taskname);
            Console.ResetColor();
            Trace.WriteLine("Starting " + taskname + " at:" + DateTime.Now);
            Stopwatch watch = new Stopwatch();
            watch.Start();
            try
            {
                taskdelegate();
            }
            catch (PingCastleException ex)
            {
                WriteInRed("[" + DateTime.Now.ToLongTimeString() + "] An exception occured when doing the task: " + taskname);
                WriteInRed(ex.Message);
                if (ex.InnerException != null)
                {
                    Trace.WriteLine(ex.InnerException.Message);
                }
            }
            // better exception message
            catch (PingCastleDataException ex)
            {
                WriteInRed("[" + DateTime.Now.ToLongTimeString() + "] An exception occured when doing the task: " + taskname);
                WriteInRed(ex.ReportName + "-" + ex.Message);
            }
            catch (UnauthorizedAccessException ex)
            {
                WriteInRed("[" + DateTime.Now.ToLongTimeString() + "] An exception occured when doing the task: " + taskname);
                WriteInRed("Exception: " + ex.Message);
                Trace.WriteLine(ex.StackTrace);
            }
            catch (SmtpException ex)
            {
                WriteInRed("[" + DateTime.Now.ToLongTimeString() + "] An exception occured when doing the task: " + taskname);
                WriteInRed("Exception: " + ex.Message);
                WriteInRed("Error code: " + ex.StatusCode);
                Trace.WriteLine("Type:" + ex.GetType().ToString());
                if (ex.InnerException != null)
                {
                    WriteInRed(ex.InnerException.Message);
                }
                WriteInRed("Check the email configuration in the .config file or the network connectivity to solve the problem");
            }
            catch (ReflectionTypeLoadException ex)
            {
                WriteInRed("Exception: " + ex.Message);
                foreach (Type type in new List<Type>(ex.Types))
                {
                    WriteInRed("Was trying to load type: " + type.FullName);
                }
                DisplayException(taskname, ex);
                return false;
            }
            // default exception message
            catch (Exception ex)
            {
                // type EndpointNotFoundException is located in Service Model using dotnet 3.0. What if run on dotnet 2.0 ?
                if (ex.GetType().FullName == "System.ServiceModel.EndpointNotFoundException")
                {
                    WriteInRed("[" + DateTime.Now.ToLongTimeString() + "] An exception occured when doing the task: " + taskname);
                    WriteInRed("Exception: " + ex.Message);
                }
                // type DirectoryServicesCOMException not found in dotnet core
                else if (ex.GetType().FullName == "System.DirectoryServices.DirectoryServicesCOMException")
                {
                    WriteInRed("An exception occured while querying the Active Directory");
                    string ExtendedErrorMessage = (string)ex.GetType().GetProperty("ExtendedErrorMessage").GetValue(ex, null);
                    int ExtendedError = (int)ex.GetType().GetProperty("ExtendedError").GetValue(ex, null);
                    WriteInRed("Exception: " + ex.Message + "(" + ExtendedErrorMessage + ")");
                    if (ExtendedError == 234)
                    {
                        WriteInRed("This error occurs when the Active Directory server is under load");
                        WriteInRed("Suggestion: try again and if the error persists, check for AD corruption");
                        WriteInRed("Try our corruption scanner to identify the object or check for AD integrity using ntdsutil.exe");
                    }
                }
                else if (ex.GetType().FullName == "System.DirectoryServices.ActiveDirectory.ActiveDirectoryServerDownException")
                {
                    WriteInRed("[" + DateTime.Now.ToLongTimeString() + "] An exception occured when doing the task: " + taskname);
                    WriteInRed("Active Directory not Found: " + ex.Message);
                }
                else if (ex.GetType().FullName == "System.DirectoryServices.ActiveDirectory.ActiveDirectoryObjectNotFoundException")
                {
                    WriteInRed("[" + DateTime.Now.ToLongTimeString() + "] An exception occured when doing the task: " + taskname);
                    WriteInRed("Active Directory Not Found: " + ex.Message);
                }
                else
                {
                    DisplayException(taskname, ex);
                    return false;
                }
            }
            watch.Stop();
            Trace.WriteLine("Stoping " + taskname + " at: " + DateTime.Now);
            Trace.WriteLine("The task " + taskname + " took " + watch.Elapsed);
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("Task " + taskname + " completed");
            Console.ResetColor();
            return true;
        }

        public static void DisplayException(string taskname, Exception ex)
        {
            if (!String.IsNullOrEmpty(taskname))
            {
                WriteInRed("[" + DateTime.Now.ToLongTimeString() + "] An exception occured when doing the task: " + taskname);
                WriteInRed("Note: you can run the program with the switch --log to get more detail");
                Trace.WriteLine("An exception occured when doing the task: " + taskname);
            }
            WriteInRed("Exception: " + ex.Message);
            Trace.WriteLine("Type:" + ex.GetType().ToString());
            var fnfe = ex as FileNotFoundException;
            if (fnfe != null)
            {
                WriteInRed("file:" + fnfe.FileName);
            }
            if (ex.GetType().ToString() == "Novell.Directory.Ldap.LdapException")
            {
                string novelMessage = null;
                int novelResultCode;
                novelResultCode = (int)ex.GetType().GetProperty("ResultCode").GetValue(ex, null);
                novelMessage = ex.GetType().GetProperty("LdapErrorMessage").GetValue(ex, null) as string;
                WriteInRed("message: " + novelMessage);
                WriteInRed("ResultCode: " + novelResultCode);
            }
            WriteInDarkRed(ex.StackTrace);
            if (ex.InnerException != null)
            {
                Trace.WriteLine("innerexception: ");
                DisplayException(null, ex.InnerException);
            }
        }


        private static void WriteInRed(string data)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(data);
            Trace.WriteLine("[Red]" + data);
            Console.ResetColor();
        }

        private static void WriteInDarkRed(string data)
        {
            Console.ForegroundColor = ConsoleColor.DarkRed;
            Console.WriteLine(data);
            Trace.WriteLine("[DarkRed]" + data);
            Console.ResetColor();
        }

        private void DisplayAdvancement(string data)
        {
            string value = "[" + DateTime.Now.ToLongTimeString() + "] " + data;
            Console.WriteLine(value);
            Trace.WriteLine(value);
        }
    }
}
