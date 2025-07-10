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
using PingCastle.Cloud.Data;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Mail;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using TinyJson;
using System.Xml.Serialization;
using System.Xml;
using PingCastle.UserInterface;
using PingCastle.Cloud.MsGraph;
using System.Security.Cryptography;

namespace PingCastle
{
    public class Tasks
    {
        public ADHealthCheckingLicense License { get; set; }

        public NetworkCredential Credential = null;
        public List<string> NodesToInvestigate = new List<string>();

        public PingCastleReportDataExportLevel ExportLevel = PingCastleReportDataExportLevel.Normal;

        private static readonly IUserInterface Ui = UserInterfaceFactory.GetUserInterface();


        Dictionary<string, string> xmlreports = new Dictionary<string, string>();
        Dictionary<string, string> htmlreports = new Dictionary<string, string>();
        Dictionary<string, DateTime> dateReports = new Dictionary<string, DateTime>();
        Dictionary<string, string> aadjsonreport = new Dictionary<string, string>();
        Dictionary<string, string> aadhtmlreport = new Dictionary<string, string>();

        private RuntimeSettings Settings;
        private AgentSettings _apiAgentSettings;

        public Tasks(RuntimeSettings settings)
        {
            Settings = settings;
        }

        public bool GenerateKeyTask()
        {
            return StartTask("Generate Key",
                    () =>
                    {
                        HealthCheckEncryption.GenerateRSAKey();
                    });
        }

        public bool GenerateAzureADKeyTask()
        {
            return StartTask("Generate AzureAD Key",
                    () =>
                    {
                    Ui.DisplayMessage(new List<string> { "Go to portal.azure.com",
                        "Open Azure Active Directory",
                        "Go to App registrations",
                        "Select new registration and create an app.",
                        "Go to Certificates & secrets and select certificates",
                        "upload the .cer file generated",
                        "",
                        "Go to Roles adn administrators",
                        "Select the role Global Reader",
                        "Click on Add assignments and add the previously created account",
                        "Make sure the App registration is listed on Assignments before leaving" });

                        var tenant = "pingcastle.com";
                        PingCastle.Cloud.Credentials.CertificateBuilder.GenerateAzureADCertificate(tenant, "vletoux", DateTime.Now.AddYears(2));
                        return;

                        //CertificateBuilder.GenerateAzureADCertificate("pingcatle.c
                    });
        }

        public bool ScannerTask()
        {
            return StartTask("Scanner",
                    () =>
                    {
                        PropertyInfo pi = Settings.Scanner.GetProperty("Name");
                        IScanner scanner = PingCastleFactory.LoadScanner(Settings.Scanner);
                        string name = pi.GetValue(scanner, null) as string;
                        DisplayAdvancement("Running scanner " + name);
                        scanner.Initialize(Settings);
                        if (scanner.QueryForAdditionalParameterInInteractiveMode() != DisplayState.Run)
                            return;
                        string file = "ad_scanner_" + name + "_" + Settings.Server + ".txt";
                        scanner.Export(file);
                        DisplayAdvancement("Results saved to " + new FileInfo(file).FullName);
                    }
                );
        }

        public bool CartoTask()
        {
            return CartoTask(false);
        }

        public bool CartoTask(bool PerformHealthCheckGenerateDemoReports = false)
        {
            List<HealthcheckAnalyzer.ReachableDomainInfo> domains = null;
            StartTask("Exploration",
                () =>
                {
                    HealthcheckAnalyzer hcroot = new HealthcheckAnalyzer();
                    hcroot.LimitHoneyPot = License.IsBasic();
                    domains = hcroot.GetAllReachableDomains(Settings.Port, Settings.Credential);
                   Ui.DisplayHighlight("List of domains that will be queried");
                    foreach (var domain in domains)
                    {
                        Ui.DisplayMessage(domain.domain);
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
                                Ui.DisplayMessage("[" + DateTime.Now.ToLongTimeString() + "] " + "Starting the analysis of " + domain);
                                HealthcheckAnalyzer hc = new HealthcheckAnalyzer();
                                hc.LimitHoneyPot = License.IsBasic();

                                var data = hc.GenerateCartoReport(domain, Settings.Port, Settings.Credential, Settings.AnalyzeReachableDomains);
                                consolidation.Add(data);
                                Ui.DisplayMessage("[" + DateTime.Now.ToLongTimeString() + "] " + "Analysis of " + domain + " completed with success");
                            }
                            catch (Exception ex)
                            {
                                Ui.DisplayMessage("[" + DateTime.Now.ToLongTimeString() + "] " + "Analysis of " + domain + " failed");
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
                Ui.DisplayMessage("Performing demo report transformation");
                Trace.WriteLine("Performing demo report transformation");
                consolidation = PingCastleReportHelper<HealthcheckData>.TransformReportsToDemo(consolidation);
            }
            if (!StartTask("Healthcheck consolidation",
                () =>
                {
                    consolidation.EnrichInformation();
                    ReportHealthCheckMapBuilder nodeAnalyzer = new ReportHealthCheckMapBuilder(consolidation, License);
                    nodeAnalyzer.Log = Ui.DisplayMessage;
                    nodeAnalyzer.CenterDomainForSimpliedGraph = Settings.CenterDomainForSimpliedGraph;
                    nodeAnalyzer.GenerateReportFile("ad_carto_full_node_map.html");
                    nodeAnalyzer.FullNodeMap = false;
                    nodeAnalyzer.CenterDomainForSimpliedGraph = Settings.CenterDomainForSimpliedGraph;
                    nodeAnalyzer.GenerateReportFile("ad_carto_simple_node_map.html");
                }
            )) return false;
            return true;
        }

        public bool RetrieveAgentSettingsTask()
        {
            if (!string.IsNullOrEmpty(Settings.apiEndpoint) && !string.IsNullOrEmpty(Settings.apiKey))
            {
                return RetrieveSettingsViaAPI();
            }
            return false;
        }

        public bool GetAgentLicense()
        {
            if (_apiAgentSettings?.License != null)
            {
                try
                {
                    var license = new ADHealthCheckingLicense(_apiAgentSettings.License);
                    license.TraceInfo();

                    if (license.EndTime > DateTime.Now)
                    {
                        License = license;
                        DisplayAdvancement("A new license has been retrieved from the API. Using it.");
                        if (!string.IsNullOrEmpty(license.CustomerNotice))
                        {
                            DisplayAdvancement(license.CustomerNotice);
                        }

                        return true;
                    }
                    else
                    {
                        DisplayAdvancement("A new license has been retrieved from the API. But the license is out-dated.");
                    }
                }
                catch (Exception ex)
                {
                    Trace.WriteLine(ex.Message);
                }
            }
            return false;
        }

        public bool AnalysisTask<T>() where T : IPingCastleReport
        {
            LoadExportLevel();

            LoadCustomRules();

            string[] servers = Settings.Server.Split(',');
            foreach (string server in servers)
            {
                AnalysisTask<T>(server);
            }
            return true;
        }

        private void LoadExportLevel()
        {
            if (!string.IsNullOrEmpty(_apiAgentSettings?.ExportLevel))
            {
                try
                {
                    // enum parsed as string to avoid a problem is a newer version of the enum is sent over the wire
                    ExportLevel = (PingCastleReportDataExportLevel)Enum.Parse(typeof(PingCastleReportDataExportLevel), _apiAgentSettings.ExportLevel);
                }
                catch (Exception)
                {
                    Trace.WriteLine("Unable to parse the level [" + _apiAgentSettings.ExportLevel + "] to one of the predefined value (" + String.Join(",", Enum.GetNames(typeof(PingCastleReportDataExportLevel))) + ")");
                }
            }
        }

        private void LoadCustomRules()
        {
            if (_apiAgentSettings?.CustomRules != null && _apiAgentSettings.CustomRules.Count != 0)
            {
                if (License.IsBasic() || License.Edition == "Auditor")
                {
                    Trace.WriteLine("Custom rules not allowed");
                }
                else
                {
                    foreach (var rule in _apiAgentSettings.CustomRules)
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

        public bool CompleteTasks()
        {
            if (!string.IsNullOrEmpty(Settings.sendXmlTo))
                SendEmail(Settings.sendXmlTo, true, false);
            if (!string.IsNullOrEmpty(Settings.sendHtmlTo))
                SendEmail(Settings.sendHtmlTo, false, true);
            if (!string.IsNullOrEmpty(Settings.sendAllTo))
                SendEmail(Settings.sendAllTo, true, true);
            if (!string.IsNullOrEmpty(Settings.sharepointdirectory))
            {
                // TODO: remove this functionality (unused ?) or add AAD support
                foreach (string domain in xmlreports.Keys)
                {
                    UploadToWebsite(HealthcheckData.GetMachineReadableFileName(domain, dateReports.ContainsKey(domain) ? dateReports[domain] : DateTime.Now), xmlreports[domain]);
                }
            }
            if (!String.IsNullOrEmpty(Settings.apiKey) && !String.IsNullOrEmpty(Settings.apiEndpoint))
                SendViaAPI(xmlreports, aadjsonreport);
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
                            var enduserReportGenerator = new ReportHealthCheckSingle(License);
                            enduserReportGenerator.GenerateReportFile(pingCastleReport, pingCastleReport.GetHumanReadableFileName());
                            DisplayAdvancement("Export level is " + ExportLevel);
                            if (ExportLevel != PingCastleReportDataExportLevel.Full)
                            {
                                DisplayAdvancement("Personal data will NOT be included in the .xml file (add --level Full to add it. Ex: PingCastle.exe --interactive --level Full)");
                            }
                            pingCastleReport.SetExportLevel(ExportLevel);
                            DataHelper<HealthcheckData>.SaveAsXml(pingCastleReport, pingCastleReport.GetMachineReadableFileName(), Settings.EncryptReport);

                        }

                        var reportConso = new ReportHealthCheckConsolidation(License);
                        reportConso.GenerateReportFile(hcconso, License, "ad_hc_summary.html");
                        ReportHealthCheckMapBuilder nodeAnalyzer = new ReportHealthCheckMapBuilder(hcconso, License);
                        nodeAnalyzer.Log = Ui.DisplayMessage;
                        nodeAnalyzer.GenerateReportFile("ad_hc_summary_full_node_map.html");
                        nodeAnalyzer.FullNodeMap = false;
                        nodeAnalyzer.CenterDomainForSimpliedGraph = Settings.CenterDomainForSimpliedGraph;
                        nodeAnalyzer.GenerateReportFile("ad_hc_summary_simple_node_map.html");
                        var mapReport = new ReportNetworkMap();
                        mapReport.GenerateReportFile(hcconso, License, "ad_hc_hilbert_map.html");
                    }
                );
        }

        public class ExportedRule
        {
            public string Type { get; set; }
            public RiskRuleCategory Category { get; set; }

            public string Description { get; set; }

            public string Documentation { get; set; }

            public int MaturityLevel { get; set; }

            public RiskModelCategory Model { get; set; }

            public string Rationale { get; set; }

            public string ReportLocation { get; set; }

            public string RiskId { get; set; }

            public string Solution { get; set; }

            public string TechnicalExplanation { get; set; }

            public string Title { get; set; }
        }

        public bool GenerateRuleList()
        {
            return StartTask("Export rules",
                    () =>
                    {
                        var rules = new List<ExportedRule>();
                        foreach (var r in PingCastle.Rules.RuleSet<HealthcheckData>.Rules)
                        {
                            rules.Add(new ExportedRule()
                            {
                                Type = "Active Directory",
                                Category = r.Category,
                                Description = r.Description,
                                Documentation = r.Documentation,
                                MaturityLevel = r.MaturityLevel,
                                Model = r.Model,
                                Rationale = r.Rationale,
                                ReportLocation = r.ReportLocation,
                                RiskId = r.RiskId,
                                //RuleComputation = r.RuleComputation,
                                Solution = r.Solution,
                                TechnicalExplanation = r.TechnicalExplanation,
                                Title = r.Title,
                            });
                        }

                        foreach (var r in PingCastle.Rules.RuleSet<HealthCheckCloudData>.Rules)
                        {
                            rules.Add(new ExportedRule()
                            {
                                Type = "Azure AD",
                                Category = r.Category,
                                Description = r.Description,
                                Documentation = r.Documentation,
                                MaturityLevel = r.MaturityLevel,
                                Model = r.Model,
                                Rationale = r.Rationale,
                                ReportLocation = r.ReportLocation,
                                RiskId = r.RiskId,
                                //RuleComputation = r.RuleComputation,
                                Solution = r.Solution,
                                TechnicalExplanation = r.TechnicalExplanation,
                                Title = r.Title,
                            });
                        }

                        var xs = new XmlSerializer(typeof(List<ExportedRule>));
                        var xmlDoc = new XmlDocument();
                        xmlDoc.PreserveWhitespace = true;
                        var nav = xmlDoc.CreateNavigator();
                        using (XmlWriter wr = nav.AppendChild())
                        using (var wr2 = new SafeXmlWriter(wr))
                        {
                            xs.Serialize(wr2, rules);
                        }
                        xmlDoc.Save("PingCastleRules.xml");

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
            if (server == "*" && Settings.InteractiveMode)
            {
                Trace.WriteLine("Setting reachable domains to on because interactive + server = *");
                Settings.AnalyzeReachableDomains = true;
            }
            if (server.Contains("*"))
            {
                List<string> domains = GetListOfDomainToExploreFromGenericName(server);
                int i = 1;

                foreach (var domain in domains)
                {
                    Ui.DisplayMessage("");
                    string display = "Starting the report for " + domain + " (" + i++ + "/" + domains.Count + ")";
                    Ui.DisplayHighlight(new List<string>
                    {
                        display,
                        new String('=', display.Length)
                    });

                    PerformTheAnalysis(domain);
                }

            }
            else
            {
                var data = PerformTheAnalysis(server);
                var hcData = data as HealthcheckData;
                // do additional exploration based on trust results ?
                Trace.WriteLine("do additional exploration based on trust results ?");
                if (hcData != null && (Settings.ExploreTerminalDomains || Settings.ExploreForestTrust))
                {
                    Trace.WriteLine("ExploreTerminalDomains is " + Settings.ExploreTerminalDomains);
                    Trace.WriteLine("ExploreForestTrust is " + Settings.ExploreForestTrust);
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
                                if (Settings.ExploreForestTrust)
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
                                if (Settings.ExploreTerminalDomains)
                                {
                                    if (!ShouldTheDomainBeNotExplored(trust.TrustPartner))
                                        domainToExamine.Add(trust.TrustPartner);
                                    else
                                        Trace.WriteLine("Domain " + trust.TrustPartner + "not to explore (terminal domain)");
                                }
                            }
                        }
                        Ui.DisplayHighlight("List of domains that will be queried");
                        Trace.WriteLine("List of domains that will be queried");
                        foreach (var domain in domainToExamine)
                        {
                            Ui.DisplayWarning(domain);
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
                    hcroot.LimitHoneyPot = License.IsBasic();
                    var reachableDomains = hcroot.GetAllReachableDomains(Settings.Port, Settings.Credential);
                    List<HealthcheckAnalyzer.ReachableDomainInfo> domainsfiltered = new List<HealthcheckAnalyzer.ReachableDomainInfo>();
                    Ui.DisplayMessage("List of domains that will be queried");
                    foreach (var reachableDomain in reachableDomains)
                    {
                        if (compareStringWithWildcard(server, reachableDomain.domain) && !ShouldTheDomainBeNotExplored(reachableDomain.domain))
                        {
                            domains.Add(reachableDomain.domain);
                            Ui.DisplayMessage(reachableDomain.domain);
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
            if (Settings.DomainToNotExplore == null)
                return false;
            foreach (string domain in Settings.DomainToNotExplore)
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
                    analyzer.LimitHoneyPot = License.IsBasic();
                    pingCastleReport = analyzer.PerformAnalyze(new PingCastleAnalyzerParameters()
                    {
                        IsPrivilegedMode = Settings.IsPrivilegedMode,
                        Server = server,
                        Port = Settings.Port,
                        Credential = Settings.Credential,
                        PerformExtendedTrustDiscovery = Settings.AnalyzeReachableDomains,
                        AdditionalNamesForDelegationAnalysis = NodesToInvestigate,
                    });
                    string domain = pingCastleReport.Domain.DomainName;
                    DisplayAdvancement("Generating html report");
                    var enduserReportGenerator = new ReportHealthCheckSingle(License);
                    htmlreports[domain] = enduserReportGenerator.GenerateReportFile(pingCastleReport, pingCastleReport.GetHumanReadableFileName());
                    DisplayAdvancement("Generating xml file for consolidation report" + (Settings.EncryptReport ? " (encrypted)" : ""));
                    DisplayAdvancement("Export level is " + ExportLevel);
                    if (ExportLevel != PingCastleReportDataExportLevel.Full)
                    {
                        DisplayAdvancement("Personal data will NOT be included in the .xml file (add --level Full to add it. Ex: PingCastle.exe --interactive --level Full)");
                    }
                    pingCastleReport.SetExportLevel(ExportLevel);
                    xmlreports[domain] = DataHelper<HealthcheckData>.SaveAsXml(pingCastleReport, pingCastleReport.GetMachineReadableFileName(), Settings.EncryptReport);
                    dateReports[domain] = pingCastleReport.GenerationDate;
                    DisplayAdvancement("Done");
                });
            return pingCastleReport;
        }

        public bool ConsolidationTask<T>() where T : IPingCastleReport
        {
            return StartTask("PingCastle report consolidation (" + typeof(T).Name + ")",
                    () =>
                    {
                        var consolidation = PingCastleReportHelper<T>.LoadXmls(Settings.InputDirectory, Settings.FilterReportDate);
                        if (consolidation.Count == 0)
                        {
                            WriteInRed("No report has been found. Please generate one with PingCastle and try again. The task will stop.");
                            return;
                        }
                        if (typeof(T) == typeof(HealthcheckData))
                        {
                            var hcconso = consolidation as PingCastleReportCollection<HealthcheckData>;
                            var report = new ReportHealthCheckConsolidation(License);
                            report.GenerateReportFile(hcconso, License, "ad_hc_summary.html");
                            ReportHealthCheckMapBuilder nodeAnalyzer = new ReportHealthCheckMapBuilder(hcconso, License);
                            nodeAnalyzer.Log = Ui.DisplayMessage;
                            nodeAnalyzer.GenerateReportFile("ad_hc_summary_full_node_map.html");
                            nodeAnalyzer.FullNodeMap = false;
                            nodeAnalyzer.CenterDomainForSimpliedGraph = Settings.CenterDomainForSimpliedGraph;
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
                        var fi = new FileInfo(Settings.InputFile);
                        if (fi.Name.EndsWith(".json.gz", StringComparison.CurrentCultureIgnoreCase))
                        {
                            HealthCheckCloudData report;
                            using (var sr = File.OpenRead(Settings.InputFile))
                            {
                                if (fi.Name.EndsWith(".gz", StringComparison.OrdinalIgnoreCase))
                                {
                                    using (var gz = new GZipStream(sr, CompressionMode.Decompress))
                                    {
                                        report = HealthCheckCloudData.LoadFromStream(gz);
                                    }
                                }
                                else
                                {
                                    report = HealthCheckCloudData.LoadFromStream(sr);
                                }
                                report.CheckIntegrity();
                                var reportGenerator = new ReportCloud();
                                reportGenerator.GenerateReportFile(report, License, "pingcastlecloud_" + report.TenantName + ".html");

                            }
                        }
                        else if (fi.Name.EndsWith(".xml", StringComparison.CurrentCultureIgnoreCase))
                        {
                            var healthcheckData = DataHelper<HealthcheckData>.LoadXml(Settings.InputFile);
                            if (healthcheckData.Level != PingCastleReportDataExportLevel.Full)
                            {
                                DisplayAdvancement("The xml report does not contain personal data. Current reporting level is: " + healthcheckData.Level);
                            }
                            var endUserReportGenerator = new ReportHealthCheckSingle(License);
                            endUserReportGenerator.GenerateReportFile(healthcheckData, healthcheckData.GetHumanReadableFileName());
                        }
                    }
                );
        }

        public bool ReloadXmlReport()
        {
            return StartTask("Reload report",
                    () =>
                    {
                        string newfile = Settings.InputFile.Replace(".xml", "_reloaded.xml");
                        string xml = null;
                        string domainFQDN = null;
                        var fi = new FileInfo(Settings.InputFile);
                        if (fi.Name.StartsWith("ad_hc_"))
                        {
                            HealthcheckData healthcheckData = DataHelper<HealthcheckData>.LoadXml(Settings.InputFile);
                            if (healthcheckData.Level != PingCastleReportDataExportLevel.Full)
                            {
                                DisplayAdvancement("The xml report does not contain personal data. Current reporting level is: " + healthcheckData.Level);
                            }

                            domainFQDN = healthcheckData.DomainFQDN;
                            DisplayAdvancement("Regenerating xml " + (Settings.EncryptReport ? " (encrypted)" : ""));
                            healthcheckData.Level = ExportLevel;
                            xml = DataHelper<HealthcheckData>.SaveAsXml(healthcheckData, newfile, Settings.EncryptReport);
                            // email sending will be handled by completedtasks
                            xmlreports[domainFQDN] = xml;
                            dateReports[domainFQDN] = healthcheckData.GenerationDate;
                        }
                        else
                        {
                            DisplayAdvancement("file ignored because it does not start with ad_hc_");
                        }
                    }
                );
        }

        public bool AnalyzeTask()
        {
            return StartTask("Analyze",
                () =>
                {
                    var analyze = new PingCastle.Cloud.Analyzer.Analyzer(Settings.AzureCredential);
                    var report = analyze.Analyze().GetAwaiter().GetResult();
                    report.SetIntegrity();
                    using (var sr = File.OpenWrite("pingcastlecloud_" + report.TenantName + ".json.gz"))
                    using (var gz = new GZipStream(sr, CompressionMode.Compress))
                    using (var sw = new StreamWriter(gz))
                    {
                        sw.Write(report.ToJsonString());
                    }
                    aadjsonreport[report.TenantName] = "pingcastlecloud_" + report.TenantName + ".json.gz";

                    var reportGenerator = new ReportCloud();
                    reportGenerator.GenerateReportFile(report, License, "pingcastlecloud_" + report.TenantName + ".html");
                    aadhtmlreport[report.TenantName] = "pingcastlecloud_" + report.TenantName + ".html";
                });
        }

        public bool UploadAllReportInCurrentDirectory()
        {
            return StartTask("Upload report",
                () =>
                {
                    if (String.IsNullOrEmpty(Settings.apiKey) || String.IsNullOrEmpty(Settings.apiEndpoint))
                        throw new PingCastleException("API end point not available");
                    var files = new List<string>(Directory.GetFiles(Directory.GetCurrentDirectory(), "*ad_*.xml", SearchOption.AllDirectories));
                    files.AddRange(Directory.GetFiles(Directory.GetCurrentDirectory(), "pingcastlecloud_*.json.gz", SearchOption.AllDirectories));
                    files.Sort();
                    DisplayAdvancement(files.Count + " files to import (only ad_*.xml files and pingcastlecloud_*.json.gz files are uploaded)");
                    var reports = new List<KeyValuePair<string, string>>();
                    var aadreports = new List<KeyValuePair<string, string>>();
                    int i = 1;
                    foreach (string file in files)
                    {
                        if (i % 50 == 0)
                        {
                            DisplayAdvancement("Uploading file up to #" + i);
                            SendViaAPI(reports, aadreports);
                            reports.Clear();
                        }
                        if (!file.EndsWith(".json.gz", StringComparison.OrdinalIgnoreCase))
                        {
                            string filename = Path.GetFileNameWithoutExtension(file);
                            reports.Add(new KeyValuePair<string, string>(filename, File.ReadAllText(file)));
                        }
                        else
                        {
                            aadreports.Add(new KeyValuePair<string, string>(file, file));
                        }
                        i++;
                    }
                    if (reports.Count > 0 || aadreports.Count > 0)
                        SendViaAPI(reports, aadreports);
                }
            );
        }

        public bool GenerateDemoReportTask()
        {
            return StartTask("Generating demo reports",
                    () =>
                    {
                        string path = Path.Combine(Settings.InputDirectory, "demo");
                        if (!Directory.Exists(path))
                        {
                            Directory.CreateDirectory(path);
                        }
                        var consolidation = PingCastleReportHelper<HealthcheckData>.LoadXmls(Settings.InputDirectory, Settings.FilterReportDate);
                        if (consolidation.Count == 0)
                        {
                            WriteInRed("No report has been found. Please generate one with PingCastle and the Health Check mode. The program will stop.");
                            return;
                        }
                        consolidation = PingCastleReportHelper<HealthcheckData>.TransformReportsToDemo(consolidation);
                        foreach (HealthcheckData data in consolidation)
                        {
                            string domain = data.DomainFQDN;
                            var endUserReportGenerator = new ReportHealthCheckSingle(License);
                            string html = endUserReportGenerator.GenerateReportFile(data, Path.Combine(path, data.GetHumanReadableFileName()));
                            data.SetExportLevel(ExportLevel);
                            string xml = DataHelper<HealthcheckData>.SaveAsXml(data, Path.Combine(path, data.GetMachineReadableFileName()), Settings.EncryptReport);
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
                Trace.WriteLine("Using proxy:" + client.Proxy.GetProxy(new Uri(Settings.apiEndpoint)));
                Trace.WriteLine("Is bypassed:" + client.Proxy.IsBypassed(new Uri(Settings.apiEndpoint)));
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
                Trace.WriteLine("apikey: " + Settings.apiKey);
                byte[] data = Encoding.Default.GetBytes("{\"apikey\": \"" + ReportHelper.EscapeJsonString(Settings.apiKey) + "\",\"location\": \"" + ReportHelper.EscapeJsonString(location) + "\"}");
                answer = client.UploadData(Settings.apiEndpoint + "api/Agent/Login", "POST", data);
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
                byte[] data = Encoding.UTF8.GetBytes(request);
                answer = client.UploadData(Settings.apiEndpoint + "api/Agent/SendReport", "POST", data);
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

        string SendViaAPIUploadOneAADReport(WebClient client, string filename, Stream filecontent)
        {
            byte[] answer = null;
            Version version = Assembly.GetExecutingAssembly().GetName().Version;
            client.Headers.Add(HttpRequestHeader.UserAgent, "PingCastle " + version.ToString(4));
            //client.Headers.Add(HttpRequestHeader.ContentType,  "multipart/form-data;
            try
            {
                Trace.WriteLine("using filename:" + filename);
                answer = client.UploadFile(Settings.apiEndpoint + "api/Agent/SendAADReport", filename);

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

        private void PullSettings(WebClient client)
        {
            Version version = Assembly.GetExecutingAssembly().GetName().Version;
            client.Headers.Add(HttpRequestHeader.ContentType, "application/json");
            client.Headers.Add(HttpRequestHeader.UserAgent, "PingCastle " + version.ToString(4));
            try
            {
                string answer = client.DownloadString(Settings.apiEndpoint + "api/Agent/GetSettings");
                Trace.WriteLine("answer:" + answer);
                DisplayAdvancement("OK");

                // TinyJson is extracted from https://github.com/zanders3/json
                // MIT License
                _apiAgentSettings = JSONParser.FromJson<AgentSettings>(answer);

                // could also use this serializer, but starting .Net 4 only (not .net 3)
                //var serializer = new System.Web.Script.Serialization.JavaScriptSerializer();
                //var deserializedResult = serializer.Deserialize<AgentSettings>(answer);
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

        void SendViaAPI(IEnumerable<KeyValuePair<string, string>> xmlreports, IEnumerable<KeyValuePair<string, string>> jsonreports)
        {
            StartTask("Send via API",
                    () =>
                    {
                        if (!Settings.apiEndpoint.EndsWith("/"))
                            Settings.apiEndpoint += "/";
                        Trace.WriteLine("apiendpoint: " + Settings.apiEndpoint);
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
                            foreach (KeyValuePair<string, string> report in jsonreports)
                            {
                                try
                                {
                                    using (var stream = File.OpenRead(report.Value))
                                    {
                                        string answer = SendViaAPIUploadOneAADReport(client, report.Key, stream);
                                        DisplayAdvancement(report.Key + "-" + (String.IsNullOrEmpty(answer) ? "OK" : answer));
                                    }
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
                        if (!Settings.apiEndpoint.EndsWith("/"))
                            Settings.apiEndpoint += "/";
                        Trace.WriteLine("apiendpoint: " + Settings.apiEndpoint);
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
                                PullSettings(client);
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
                    Files.Add(Attachment.CreateAttachmentFromString(xmlreports[domain], HealthcheckData.GetMachineReadableFileName(domain, dateReports.ContainsKey(domain) ? dateReports[domain] : DateTime.Now)));
                }
                foreach (string tenant in aadjsonreport.Keys)
                {
                    if (!domains.Contains(tenant))
                        domains.Add(tenant);
                    Files.Add(new Attachment(aadjsonreport[tenant]));
                }
            }
            if (html)
            {
                foreach (string domain in htmlreports.Keys)
                {
                    if (!domains.Contains(domain))
                        domains.Add(domain);
                    Files.Add(Attachment.CreateAttachmentFromString(htmlreports[domain], HealthcheckData.GetHumanReadableFileName(domain, dateReports.ContainsKey(domain) ? dateReports[domain] : DateTime.Now)));
                }
                foreach (string tenant in aadhtmlreport.Keys)
                {
                    if (!domains.Contains(tenant))
                        domains.Add(tenant);
                    Files.Add(new Attachment(aadhtmlreport[tenant]));
                }
            }
            if (Files.Count == 0)
                return;
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
                        if (!String.IsNullOrEmpty(Settings.mailNotification))
                        {
                            message.Headers.Add("Disposition-Notification-To", Settings.mailNotification);
                            message.Headers.Add("Return-Receipt-To", Settings.mailNotification);
                        }
                        SmtpClient client = new SmtpClient();
                        if (Settings.smtpTls)
                            client.EnableSsl = true;
                        else
                            client.EnableSsl = (client.Port == 587 || client.Port == 465);
                        if (!String.IsNullOrEmpty(Settings.smtpLogin) || !String.IsNullOrEmpty(Settings.smtpPassword))
                            client.Credentials = new NetworkCredential(Settings.smtpLogin, Settings.smtpPassword);
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
                        if (!String.IsNullOrEmpty(Settings.sharepointuser))
                            client.Credentials = new NetworkCredential(Settings.sharepointuser, Settings.sharepointpassword);
                        else
                            client.UseDefaultCredentials = true;
                        string url = Settings.sharepointdirectory + (Settings.sharepointdirectory.EndsWith("/") ? null : "/") + filename;
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
                        bot.Run(Settings.botPipe);
                    }
            );
        }

        public bool ExportTask()
        {
            return StartTask("Running Export",
                    () =>
                    {

                        PropertyInfo pi = Settings.Export.GetProperty("Name");
                        IExport export = PingCastleFactory.LoadExport(Settings.Export);
                        string name = pi.GetValue(export, null) as string;
                        DisplayAdvancement("Running export " + name);
                        export.Initialize(Settings);
                        if (export.QueryForAdditionalParameterInInteractiveMode() != DisplayState.Run)
                            return;
                        string file = "ad_export_" + name + "_" + Settings.Server + ".txt";
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
            Ui.DisplayHighlight("Starting the task: " + taskname);
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
                WriteInRed("[" + DateTime.Now.ToLongTimeString() + "] An exception occured when doing the task: " + taskname);
                WriteInRed("Exception: " + ex.Message);
                foreach (Type type in new List<Type>(ex.Types))
                {
                    WriteInRed("Was trying to load type: " + type.FullName);
                }
                DisplayException(taskname, ex);
                return false;
            }
            catch(CryptographicException cex)
            {
                WriteInRed("[" + DateTime.Now.ToLongTimeString() + "] An cryptographic error occured when doing the task: " + taskname);

                // The only discriminator we have to work with is the message
                string errorMessage = cex.Message.Trim('\n', '\r') switch
                {
                    "Invalid algorithm specified." => "An Invalid algorithm was specified. This usually means that the certificate used to authenticate does not contain the providers \"Microsoft Enhanced RSA and AES Cryptographic Provider\"",
                    _ => cex.Message
                };

                WriteInRed(errorMessage);
                return false;
            }
            // default exception message
            catch (Exception ex)
            {
                WriteInRed("[" + DateTime.Now.ToLongTimeString() + "] An exception occured when doing the task: " + taskname);
                // type EndpointNotFoundException is located in Service Model using dotnet 3.0. What if run on dotnet 2.0 ?
                if (ex.GetType().FullName == "System.ServiceModel.EndpointNotFoundException")
                {
                    WriteInRed("Exception: " + ex.Message);
                }
                else if (ex.GetType().FullName == "System.Runtime.InteropServices.COMException")
                {
                    WriteInRed("Exception: " + ex.Message);
                    WriteInRed("HRESULT: " + ex.HResult);
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
                    WriteInRed("Active Directory not Found: " + ex.Message);
                }
                else if (ex.GetType().FullName == "System.DirectoryServices.ActiveDirectory.ActiveDirectoryObjectNotFoundException")
                {
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
            Ui.DisplayHighlight("Task " + taskname + " completed");
            return true;
        }

        public static void DisplayException(string taskName, Exception ex, bool showStackTrace = false)
        {
            try
            {
                if (!String.IsNullOrEmpty(taskName))
                {
                    WriteInRed("[" + DateTime.Now.ToLongTimeString() + "] An exception occured when doing the task: " + taskName);
                    WriteInRed("Note: you can run the program with the switch --log to get more detail");
                    Trace.WriteLine("An exception occured when doing the task: " + taskName);
                }
                WriteInRed("Exception: " + ex.Message);
                Trace.WriteLine("Type:" + ex.GetType());

                if (ex is System.DirectoryServices.Protocols.LdapException ldapEx)
                {
                    HandleLdapException(ldapEx);
                }

                if (showStackTrace)
                {
                    WriteInDarkRed(ex.StackTrace);
                }
                if (ex.InnerException != null)
                {
                    Trace.WriteLine("innerexception: ");
                    DisplayException(null, ex.InnerException);
                }
            }
            catch(Exception exc)
            {
                // Basic handling in case we have an error in error handling.
                WriteInRed("Exception: " + exc.Message);
            }
        }

        private static void HandleLdapException(System.DirectoryServices.Protocols.LdapException ex)
        {
            WriteInRed("message: " + (ex.ServerErrorMessage ?? "Could not retrieve error message"));
            WriteInRed("ResultCode: " + ex.ErrorCode);
        }

        private static void WriteInRed(string data)
        {
            UserInterfaceFactory.GetUserInterface().DisplayError(data);
            Trace.WriteLine("[Red]" + data);
        }

        private static void WriteInDarkRed(string data)
        {
            UserInterfaceFactory.GetUserInterface().DisplayStackTrace(data);
            Trace.WriteLine("[DarkRed]" + data);
        }

        private void DisplayAdvancement(string data)
        {
            string value = "[" + DateTime.Now.ToLongTimeString() + "] " + data;
            Ui.DisplayMessage(value);
            Trace.WriteLine(value);
        }
    }
}
