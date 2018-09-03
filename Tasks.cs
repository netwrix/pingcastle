//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Database;
using PingCastle.Export;
using PingCastle.Healthcheck;
using PingCastle.Scanners;
using PingCastle.misc;
using PingCastle.NullSession;
using PingCastle.Reporting;
using PingCastle.shares;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.DirectoryServices.ActiveDirectory;
using System.IO;
using System.Net;
using System.Net.Mail;
using System.Reflection;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using PingCastle.Data;

namespace PingCastle
{
    public class Tasks
    {
		public ADHealthCheckingLicense License { get; set; }
        public int NullSessionEnumerationLimit = 5;
        public string Server = null;
        public int ADWSPort = 0;
        public NetworkCredential Credential = null;
        public int MaxDepth = 30;
        public int MaxNodes = 1000;
        public List<string> NodesToInvestigate = new List<string>();
        public bool AutoReport = false;
        public bool ReverseDirection = false;
        public string FileOrDirectory = null;
        public HealthcheckDataLevel ExportLevel = HealthcheckDataLevel.Normal;
        public int NumberOfDepthForSplit = 0;
        public string sendXmlTo;
        public string sendHtmlTo;
        public string sendAllTo;
        public string sharepointdirectory;
        public string sharepointuser;
        public string sharepointpassword;
        public string CenterDomainForSimpliedGraph = null;
        public  bool ExploreTerminalDomains;
        public  bool ExploreForestTrust;
        public  List<string> DomainToNotExplore;
        public bool EncryptReport = false;
        public bool InteractiveMode = false;
        public string mailNotification;
        public string smtpLogin;
        public string smtpPassword;
        public DateTime FilterReportDate = DateTime.MaxValue;
        public bool smtpTls;
		public string EnumInboundSid;
		public Type Scanner;
        public string apiEndpoint;
        public string apiKey;
        public bool AnalyzeReachableDomains;

        public bool GenerateKeyTask()
        {
            return StartTask("Generate Key",
                    () =>
                    {
                        HealthCheckEncryption.GenerateRSAKey();
                    });
        }

		/*
        public bool ExportHCRuleTask()
        {
            return StartTask("Export Healthcheck rules",
                    () =>
                    {
                        HealthcheckRules rules = new HealthcheckRules();
                        rules.GenerateRuleDescriptionFile("rules-V" + Assembly.GetExecutingAssembly().GetName().Version + ".xlsx");
                    }
                );
        }
		*/

        public bool NullSessionTask()
        {
            return StartTask("Null Session",
                    () =>
                    {
                        NullSessionTester session = new NullSessionTester(Server,
                            (NTAccount server) => { Console.WriteLine(server.Value); });
                        bool enabled = false;
                        Console.WriteLine("Testing MS-SAMR");
                        if (session.EnumerateAccount(TypeOfEnumeration.Samr, NullSessionEnumerationLimit))
                        {
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine("Null session is enabled (at least MS-SAMR)");
                            Console.ResetColor();
                            enabled = true;
                        }
                        else
                        {
                            Console.WriteLine("MS-SAMR disabled");
                        }
                        if (!enabled)
                        {
                            Console.WriteLine("Testing MS-LSAT");
                            if (session.EnumerateAccount(TypeOfEnumeration.Lsa, NullSessionEnumerationLimit))
                            {
                                Console.ForegroundColor = ConsoleColor.Red;
                                Console.WriteLine("Null session is enabled (only MS-LSAT)");
                                Console.ResetColor();
                                enabled = true;
                            }
                            else
                            {
                                Console.WriteLine("MS-LSAT disabled");
                            }
                        }
                        if (!enabled)
                        {
                            Console.WriteLine("Null session is disabled");
                        }
                    }
                );
        }


		public bool ScannerTask()
		{
			return StartTask("Scanner",
					() =>
					{
						PropertyInfo pi = Scanner.GetProperty("Name");
						IScanner scanner = (IScanner) Activator.CreateInstance(Scanner);
						string name = pi.GetValue(scanner, null) as string;
						scanner.Initialize(Server, ADWSPort, Credential);
						scanner.Export("ad_scanner_" + name + "_" + Server + ".txt");
					}
				);
		}

		public bool NullTrustsTask()
		{
			return StartTask("Null Session",
                    () =>
                    {
						nrpc session = new nrpc();;
                        Console.WriteLine("Trusts obtained via null session");
						List<TrustedDomain> domains;
						int res = session.DsrEnumerateDomainTrusts(Server, 0x3F, out domains);
						if (res != 0)
						{
							Console.WriteLine("Error " + res + " (" + new Win32Exception(res).Message + ")");
							return;
						}
						Console.WriteLine("Success");
						int i = 0;
						foreach (var domain in domains)
						{
							Console.WriteLine("=== Trust " + i++ + "===");
							Console.WriteLine("DnsDomainName: " + domain.DnsDomainName);
							Console.WriteLine("NetbiosDomainName: " + domain.NetbiosDomainName);
							Console.WriteLine("TrustAttributes: " + TrustAnalyzer.GetTrustAttribute(domain.TrustAttributes) + " (" + domain.TrustAttributes + ")");
							Console.WriteLine("TrustType: " + TrustAnalyzer.GetTrustType(domain.TrustType) + " (" + domain.TrustType + ")");
							Console.WriteLine("Flags: " + domain.Flags);
							Console.WriteLine("DomainGuid: " + domain.DomainGuid);
							Console.WriteLine("DomainSid: " + domain.DomainSid);
							Console.WriteLine("ParentIndex: " + domain.ParentIndex);
						}
					}
				);
		}

		public bool EnumInboundTrustTask()
		{
			return StartTask("Enumerate account from inbound trust",
					() =>
					{
						AccountEnumeratorViaTrust session = new AccountEnumeratorViaTrust(Server,
							(SecurityIdentifier sid, NTAccount server) => { Console.WriteLine(server.Value); });
						Console.WriteLine("Getting the domain sid");
						SecurityIdentifier EnumInboundTrustSid = null;
						if (EnumInboundSid.StartsWith("S-1-5-", StringComparison.InvariantCultureIgnoreCase))
						{
							try
							{
								EnumInboundTrustSid = new SecurityIdentifier(EnumInboundSid);
							}
							catch (Exception ex)
							{
								throw new ApplicationException("The SID couldn't be parsed (error:" + ex.Message + ")");
							}
						}
						else
						{
							EnumInboundTrustSid = NativeMethods.GetSidFromDomainName(Server, EnumInboundSid);
						}
						if (EnumInboundSid == null)
						{
							throw new ApplicationException("The domain " + EnumInboundSid + " couldn't be translated to a sid");
						}
						Console.WriteLine("Using the domain SID " + EnumInboundTrustSid.Value);
						session.EnumerateAccount(EnumInboundTrustSid, int.MaxValue);
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
                    domains = hcroot.GetAllReachableDomains(ADWSPort, Credential);
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("List of domains that will be queried");
                    Console.ResetColor();
                    foreach (var domain in domains)
                    {
                        Console.WriteLine(domain.domain);
                    }
                });
            HealthcheckDataCollection consolidation = new HealthcheckDataCollection();
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
                                hc.NumberOfDepthForSplit = NumberOfDepthForSplit;
                                hc.AnalyzeReachableDomains = AnalyzeReachableDomains;
                                hc.GenerateCartoReport(domain, ADWSPort, Credential);
                                consolidation.Add(hc.healthcheckData);
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
                consolidation = HealthcheckDataHelper.TransformReportsToDemo(consolidation);
            }
            if (!StartTask("Healthcheck consolidation",
                () =>
                {
                    HealthcheckAnalyzer hc = new HealthcheckAnalyzer();
                    HealthCheckReportMapBuilder nodeAnalyzer = new HealthCheckReportMapBuilder(consolidation);
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

        public bool HeatlthCheckTask()
        {
            Dictionary<string, string> xmlreports = new Dictionary<string, string>();
            Dictionary<string, string> htmlreports = new Dictionary<string, string>();
            string[] servers = Server.Split(',');
            foreach (string server in servers)
            {
                HeatlthCheckTask(server, xmlreports, htmlreports);
            }
            if (!String.IsNullOrEmpty(sendXmlTo))
                SendEmail(sendXmlTo, true, false, xmlreports, htmlreports);
            if (!String.IsNullOrEmpty(sendHtmlTo))
                SendEmail(sendHtmlTo, false, true, xmlreports, htmlreports);
            if (!String.IsNullOrEmpty(sendAllTo))
                SendEmail(sendAllTo, true, true, xmlreports, htmlreports);
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

        public bool HeatlthCheckTask(string server, Dictionary<string, string> xmlreports, Dictionary<string, string> htmlreports)
        {
            Trace.WriteLine("Working on " + server);
            if (server == "*" && InteractiveMode)
            {
                Trace.WriteLine("Setting reachable domains to on because interactive + server = *");
                AnalyzeReachableDomains = true;
            }
            if (server.Contains("*"))
            {
                List<HealthcheckAnalyzer.ReachableDomainInfo> domains = null;
                StartTask("Exploration",
                    () =>
                    {
                        HealthcheckAnalyzer hcroot = new HealthcheckAnalyzer();
                        domains = hcroot.GetAllReachableDomains(ADWSPort, Credential);
                        List<HealthcheckAnalyzer.ReachableDomainInfo> domainsfiltered = new List<HealthcheckAnalyzer.ReachableDomainInfo>();
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine("List of domains that will be queried");
                        Console.ResetColor();
                        foreach (var domain in domains)
                        {
                            if (compareStringWithWildcard(server, domain.domain) && !ShouldTheDomainBeNotExplored(domain.domain))
                            {
                                domainsfiltered.Add(domain);
                                Console.WriteLine(domain.domain);
                            }
                        }
                        domains = domainsfiltered;
                    });
                int i = 1;

                foreach (var domain in domains)
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("");
                    string display = "Starting the report for " + domain.domain + " (" + i++ + "/" + domains.Count + ")";
                    Console.WriteLine(display);
                    Console.WriteLine(new String('=', display.Length));
                    Console.ResetColor();
                    HealthcheckData hcData;
                    HealthcheckSubTask(domain.domain, xmlreports, htmlreports, AnalyzeReachableDomains, out hcData);
                }

            }
            else
            {
                HealthcheckData hcData;
                bool output = HealthcheckSubTask(server, xmlreports, htmlreports, AnalyzeReachableDomains, out hcData);
                // do additional exploration based on trust results ?
                if (output && (ExploreTerminalDomains || ExploreForestTrust))
                {
					if (hcData.Trusts != null)
                    {
                        List<string> domainToExamine = new List<string>();
                        foreach (var trust in hcData.Trusts)
                        {
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
                                    if (trust.KnownDomains != null)
                                    {
                                        foreach (var di in trust.KnownDomains)
                                        {
                                            if (!ShouldTheDomainBeNotExplored(di.DnsName))
                                                domainToExamine.Add(di.DnsName);
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
                                }
                            }
                        }
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine("List of domains that will be queried");
                        Console.ResetColor();
                        foreach (var domain in domainToExamine)
                        {
                            Console.WriteLine(domain);
                        }
                        foreach (string domain in domainToExamine)
                        {
                            HealthcheckData hcDataTemp;
                            HealthcheckSubTask(domain, xmlreports, htmlreports, AnalyzeReachableDomains, out hcDataTemp);
                        }
                    }
                }
                return output;
            }
            return true;
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

        bool HealthcheckSubTask(string server, Dictionary<string, string> xmlreports, Dictionary<string, string> htmlreports, bool DoAnalyzeReachableDomains, out HealthcheckData data)
        {
            HealthcheckData reportTemp = null;
            bool status = StartTask("Healthcheck for " + server,
                () =>
                {
					HealthcheckAnalyzer hc = new HealthcheckAnalyzer();
                    hc.AnalyzeReachableDomains = DoAnalyzeReachableDomains;
                    hc.NumberOfDepthForSplit = NumberOfDepthForSplit;
					hc.GenerateReport(server, ADWSPort, Credential);
					reportTemp = hc.healthcheckData;
					string domain = hc.healthcheckData.DomainFQDN;
					DisplayAdvancement("Generating html report");
					HealthCheckReportSingle report = new HealthCheckReportSingle(hc.healthcheckData, License);
					htmlreports[domain] = report.GenerateReportFile("ad_hc_" + domain + ".html");
					DisplayAdvancement("Generating xml file for consolidation report" + (EncryptReport ? " (encrypted)" : ""));
					hc.healthcheckData.Level = ExportLevel;
					xmlreports[domain] = DataHelper<HealthcheckData>.SaveAsXml(hc.healthcheckData, "ad_hc_" + domain + ".xml", EncryptReport);
                });
            data = reportTemp;
            return status;
        }

        public bool ConsolidationTask()
        {
            return StartTask("Healthcheck consolidation",
                    () =>
                    {
                        HealthcheckAnalyzer hc = new HealthcheckAnalyzer();
                        if (String.IsNullOrEmpty(FileOrDirectory))
                        {
                            FileOrDirectory = Directory.GetCurrentDirectory();
                        }
                        if (!Directory.Exists(FileOrDirectory))
                        {
                            WriteInRed("The directory " + FileOrDirectory + " doesn't exist");
                            return;
                        }
                        HealthcheckDataCollection consolidation = HealthcheckDataHelper.LoadXmls(FileOrDirectory, FilterReportDate);
                        if (consolidation.Count == 0)
                        {
                            WriteInRed("No report has been found. The program will stop");
                            return;
                        }
						HealthCheckReportConsolidation report = new HealthCheckReportConsolidation(consolidation);
                        report.GenerateReportFile("ad_hc_summary.html");
                        HealthCheckReportMapBuilder nodeAnalyzer = new HealthCheckReportMapBuilder(consolidation);
                        nodeAnalyzer.Log = Console.WriteLine;
                        nodeAnalyzer.GenerateReportFile("ad_hc_summary_full_node_map.html");
						nodeAnalyzer.FullNodeMap = false;
						nodeAnalyzer.CenterDomainForSimpliedGraph = CenterDomainForSimpliedGraph;
						nodeAnalyzer.GenerateReportFile("ad_hc_summary_simple_node_map.html");
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
						if (FileOrDirectory.StartsWith("ad_cg_"))
						{
							CompromiseGraphData data = DataHelper<CompromiseGraphData>.LoadXml(FileOrDirectory);
							HealthCheckReportCompromiseGraph report = new HealthCheckReportCompromiseGraph(data, License);
							report.GenerateReportFile("ad_cg_" + data.DomainFQDN + ".html");
						}
						else
						{
							HealthcheckData healthcheckData = DataHelper<HealthcheckData>.LoadXml(FileOrDirectory);
							HealthCheckReportSingle report = new HealthCheckReportSingle(healthcheckData, License);
							report.GenerateReportFile("ad_hc_" + healthcheckData.DomainFQDN + ".html");
						}
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
						if (FileOrDirectory.StartsWith("ad_hc_"))
						{
							HealthcheckData healthcheckData = DataHelper<HealthcheckData>.LoadXml(FileOrDirectory);
							domainFQDN = healthcheckData.DomainFQDN;
							DisplayAdvancement("Regenerating xml " + (EncryptReport ? " (encrypted)" : ""));
							healthcheckData.Level = ExportLevel;
							xml = DataHelper<HealthcheckData>.SaveAsXml(healthcheckData, newfile, EncryptReport);
						}
						else if (FileOrDirectory.StartsWith("ad_cg_"))
						{
							CompromiseGraphData data = DataHelper<CompromiseGraphData>.LoadXml(FileOrDirectory);
							domainFQDN = data.DomainFQDN;
							DisplayAdvancement("Regenerating xml " + (EncryptReport ? " (encrypted)" : ""));
							xml = DataHelper<CompromiseGraphData>.SaveAsXml(data, newfile, EncryptReport);
						}
                        if (!String.IsNullOrEmpty(apiKey) && !String.IsNullOrEmpty(apiEndpoint))
                            SendViaAPI(new Dictionary<string, string>() { { FileOrDirectory, xml } });
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
                        throw new ApplicationException("API end point not available");
                    var files = new List<string>(Directory.GetFiles(Directory.GetCurrentDirectory(), "ad_*.xml", SearchOption.AllDirectories));
                    files.Sort();
                    DisplayAdvancement(files.Count + " files to import (only ad_*.xml files are uploaded)");
                    var reports = new List<KeyValuePair<string, string>>();
                    int i = 1;
                    foreach(string file in files)
                    {
                        if (i%50==0)
                        {
                            DisplayAdvancement("Uploading file up to #" + i);
                            SendViaAPI(reports);
                            reports.Clear();
                        }
                        string filename = Path.GetFileNameWithoutExtension(file);
                        reports.Add(new KeyValuePair<string,string>(filename, File.ReadAllText(file)));
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
                        HealthcheckDataCollection consolidation = HealthcheckDataHelper.LoadXmls(FileOrDirectory, FilterReportDate);
                        if (consolidation.Count == 0)
                        {
                            WriteInRed("No report has been found. The program will stop");
                            return;
                        }
                        consolidation = HealthcheckDataHelper.TransformReportsToDemo(consolidation);
                        foreach (HealthcheckData data in consolidation)
                        {
                            string domain = data.DomainFQDN;
                            HealthCheckReportSingle report = new HealthCheckReportSingle(data, License);
                            string newfile = Path.Combine(path, "ad_hc_" + domain + ".html");
                            string html = report.GenerateReportFile(newfile);
							newfile = Path.Combine(path, "ad_hc_" + domain + ".xml");
							data.Level = ExportLevel;
							string xml = DataHelper<HealthcheckData>.SaveAsXml(data, newfile, EncryptReport);
                        }

                    }
                );
        }

        public bool AdvancedLiveAnalysisTask()
        {
            return StartTask("Compromission Graph analysis",
                    () =>
                    {
						DisplayAdvancement("Doing the data collection");
                        ExportDataFromActiveDirectoryLive export = new ExportDataFromActiveDirectoryLive(Server, ADWSPort, Credential);
                        export.ExportData(NodesToInvestigate);
						DisplayAdvancement("Doing the analysis");
                        ReportGenerator reporting = new ReportGenerator(export.Storage, MaxDepth, MaxNodes);
						var data = reporting.GenerateReport(NodesToInvestigate);
						DisplayAdvancement("Generating the report");
						var reportGenerator = new HealthCheckReportCompromiseGraph(data, License);
						reportGenerator.GenerateReportFile("ad_cg_" + data.DomainFQDN + ".html");
						string xml = DataHelper<CompromiseGraphData>.SaveAsXml(data, "ad_cg_" + data.DomainFQDN + ".xml", EncryptReport);
						if (!String.IsNullOrEmpty(apiKey) && !String.IsNullOrEmpty(apiEndpoint))
							SendViaAPI(new Dictionary<string, string>() { { FileOrDirectory, xml } });
						if (!String.IsNullOrEmpty(sharepointdirectory))
							UploadToWebsite("ad_cg_" + data.DomainFQDN + ".xml", xml);
						if (!String.IsNullOrEmpty(sendXmlTo))
							SendEmail(sendXmlTo, new List<string> { data.DomainFQDN },
								new List<Attachment> { Attachment.CreateAttachmentFromString(xml, "ad_cg_" + data.DomainFQDN + ".xml") });
						if (!String.IsNullOrEmpty(sendHtmlTo))
							WriteInRed("Html report ignored when xml file used as input");
						if (!String.IsNullOrEmpty(sendAllTo))
						{
							WriteInRed("Html report ignored when xml file used as input");
							SendEmail(sendAllTo, new List<string> { data.DomainFQDN },
								new List<Attachment> { Attachment.CreateAttachmentFromString(xml, "ad_cg_" + data.DomainFQDN + ".xml") });
						}
						DisplayAdvancement("Done");
                    }
                );
        }

        // return JWT token
        void SendViaAPIGetJwtToken(WebClient client)
        {
            ServicePointManager.Expect100Continue = false;
            client.UseDefaultCredentials = true;
            client.Proxy = WebRequest.DefaultWebProxy;
            Version version = Assembly.GetExecutingAssembly().GetName().Version;
            client.Headers.Add(HttpRequestHeader.ContentType, "application/json");
            client.Headers.Add(HttpRequestHeader.UserAgent, "PingCastle " + version.ToString(4));
            //client.Headers.Add("Authorization", token);
            string token;
            byte[] answer = null;
            try
            {
                string location = Dns.GetHostEntry(Environment.MachineName).HostName;
                byte[] data = Encoding.Default.GetBytes("{\"apikey\": \"" + HealthCheckReportMapBuilder.EscapeJsonString(apiKey) + "\",\"location\": \"" + HealthCheckReportMapBuilder.EscapeJsonString(location) + "\"}");
                answer = client.UploadData(apiEndpoint + "api/Agent/Login", "POST", data);
                token = Encoding.Default.GetString(answer);
                client.Headers.Add(HttpRequestHeader.Authorization, token);
            }
            catch (WebException ex)
            {
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
                var request = "{\"xmlReport\": \"" + HealthCheckReportMapBuilder.EscapeJsonString(xml) + "\",\"filename\":\"" + HealthCheckReportMapBuilder.EscapeJsonString(filename) + "\"}";
                byte[] data = Encoding.ASCII.GetBytes(request);
                answer = client.UploadData(apiEndpoint + "api/Agent/SendReport", "POST", data);
                return Encoding.Default.GetString(answer);
            }
            catch (WebException ex)
            {
                if (ex.Response != null)
                {
                    var responseStream = ex.Response.GetResponseStream();
                    if (responseStream != null)
                    {
                        using (var reader = new StreamReader(responseStream))
                        {
                            string responseText = reader.ReadToEnd();
                            throw new ApplicationException(responseText);
                        }
                    }
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
                            foreach(KeyValuePair<string, string> report in xmlreports)
                            {
                                try
                                {
                                    string answer = SendViaAPIUploadOneReport(client, report.Key, report.Value);
                                    DisplayAdvancement(report.Key + "-" + (String.IsNullOrEmpty(answer) ? "OK" : answer));
                                }
                                catch(Exception ex)
                                {
                                    WriteInRed(report.Key + "-" + ex.Message);
                                }
                            }
                        }
                    });
        }

        void SendEmail(string email, List<string> domains, List<Attachment> Files)
        {
            string body = @"Hello,

This is the PingCastle program sending reports for:
- " + String.Join("\r\n- ", domains.ToArray());
            SendEmail(email, "[PingCastle] Reports for " + String.Join(",", domains.ToArray()), body, Files);
        }

        void SendEmail(string email, bool xml, bool html, Dictionary<string, string> xmlreports, Dictionary<string, string> htmlreports)
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
			catch (ActiveDirectoryObjectNotFoundException ex)
			{
				WriteInRed("[" + DateTime.Now.ToLongTimeString() + "] An exception occured when doing the task: " + taskname);
				WriteInRed("Active Directory Not Found: " + ex.Message);
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
				foreach(Type type in new List<Type>(ex.Types))
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
            WriteInRed(ex.StackTrace);
            Trace.WriteLine(ex.Message);
            Trace.WriteLine(ex.StackTrace);
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

        private void DisplayAdvancement(string data)
        {
            string value = "[" + DateTime.Now.ToLongTimeString() + "] " + data;
            Console.WriteLine(value);
            Trace.WriteLine(value);
        }
	}
}
