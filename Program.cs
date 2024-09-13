﻿//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.ADWS;
using PingCastle.Data;
using PingCastle.Exports;
using PingCastle.Graph.Reporting;
using PingCastle.Healthcheck;
using PingCastle.Report;
using PingCastle.Scanners;
using PingCastle.Cloud.Common;
using PingCastle.Cloud.RESTServices.Azure;
using PingCastle.Cloud.Tokens;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using PingCastleCommon;

namespace PingCastle
{
    enum PossibleTasks
    {
        GenerateKey,
        Scanner,
        Export,
        Carto,
        Bot,
        ADHealthCheck,
        ADConso,
        HCRules,
        Regen,
        Reload,
        DemoReport,
        UploadAllRports,
        FakeReport,
        CloudHealthCheck,
        ExportRulesXml,
    }

    [LicenseProvider(typeof(PingCastle.ADHealthCheckingLicenseProvider))]
    public class Program : IPingCastleLicenseInfo
    {
        
        Dictionary<PossibleTasks, Func<bool>> actions;
        Dictionary<PossibleTasks, string[]> requiredSettings;
        List<PossibleTasks> requestedActions = new List<PossibleTasks>();

        RuntimeSettings settings;
        Tasks tasks;

        public Program()
        {
            settings = new RuntimeSettings();
            tasks = new Tasks(settings);
        }

        public static void Main(string[] args)
        {
            try
            {
                // enable the use of TLS1.0
                //AppContext.SetSwitch("Switch.System.Net.DontEnableSchUseStrongCrypto", true);
                // enable the use of TLS1.2 if enabled on the system
                //AppContext.SetSwitch("Switch.System.Net.DontEnableSystemDefaultTlsVersions", false);

                AppDomain.CurrentDomain.UnhandledException += new UnhandledExceptionEventHandler(CurrentDomain_UnhandledException);
                AppDomain.CurrentDomain.AssemblyResolve += new ResolveEventHandler(CurrentDomain_AssemblyResolve);
                Trace.WriteLine("Running on dotnet:" + Environment.Version);
                Program program = new Program();
                program.Run(args);
                // dispose the http logger
                HttpClientHelper.EnableLoging(null);
                if (program.settings.InteractiveMode)
                {
                    Console.WriteLine("=============================================================================");
                    Console.WriteLine("Program launched in interactive mode - press any key to terminate the program");
                    Console.WriteLine("=============================================================================");
                    Console.ReadKey();
                }
            }
            catch (Exception ex)
            {
                // dispose the http logger
                HttpClientHelper.EnableLoging(null);
                Tasks.DisplayException("main program", ex);
            }
        }

        static void CurrentDomain_UnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            Tasks.DisplayException("application domain", e.ExceptionObject as Exception);
        }

        static Assembly CurrentDomain_AssemblyResolve(object sender, ResolveEventArgs args)
        {
            // hook required for "System.Runtime.Serialization.ContractNamespaceAttribute"
            var name = new AssemblyName(args.Name);
            Trace.WriteLine("Needing assembly " + name + " unknown (" + args.Name + ")");
            return null;
        }

        private void Run(string[] args)
        {
            ADHealthCheckingLicense license = null;
            Version version = Assembly.GetExecutingAssembly().GetName().Version;
            Trace.WriteLine("PingCastle version " + version.ToString(4));
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i].Equals("--debug-license", StringComparison.InvariantCultureIgnoreCase))
                {
                    EnableLogConsole();
                }
                else if (args[i].Equals("--license", StringComparison.InvariantCultureIgnoreCase) && i + 1 < args.Length)
                {
                    _serialNumber = args[++i];
                }
                else if (args[i].Equals("--out", StringComparison.InvariantCultureIgnoreCase) && i + 1 < args.Length)
                {
                    string filename = args[++i];
                    FilesValidator.CheckPathTraversal(filename);
    
                    var fi = new FileInfo(filename);
                    if (!Directory.Exists(fi.DirectoryName))
                    {
                        Directory.CreateDirectory(fi.DirectoryName);
                    }
                    Stream stream = File.Open(filename, FileMode.Create, FileAccess.Write, FileShare.Read);
                    StreamWriter writer = new StreamWriter(stream);
                    writer.AutoFlush = true;
                    Console.SetOut(writer);
                }
            }
            Trace.WriteLine("Starting the license checking");
            try
            {
                license = LicenseManager.Validate(typeof(Program), this) as ADHealthCheckingLicense;
            }
            catch (Exception ex)
            {
                Trace.WriteLine("the license check failed - please check that the .config file is in the same directory");
                WriteInRed(ex.Message);
                if (args.Length == 0)
                {
                    Console.WriteLine("=============================================================================");
                    Console.WriteLine("Program launched in interactive mode - press any key to terminate the program");
                    Console.WriteLine("=============================================================================");
                    Console.ReadKey();
                }
                return;
            }
            Trace.WriteLine("License checked");
            Trace.WriteLine("CustomerNotice: " + license.CustomerNotice);
            Trace.WriteLine("DomainLimitation: " + license.DomainLimitation);
            Trace.WriteLine("DomainNumberLimit: " + license.DomainNumberLimit);
            Trace.WriteLine("Edition: " + license.Edition);
            Trace.WriteLine("EndTime: " + license.EndTime);
            if (license.EndTime < DateTime.Now)
            {
                WriteInRed("The program is unsupported since: " + license.EndTime.ToString("u") + ")");
                if (args.Length == 0)
                {
                    Console.WriteLine("=============================================================================");
                    Console.WriteLine("Program launched in interactive mode - press any key to terminate the program");
                    Console.WriteLine("=============================================================================");
                    Console.ReadKey();
                }
                return;
            }
            if (license.EndTime < DateTime.MaxValue)
            {
                Console.WriteLine();
            }
            tasks.License = license;

            actions = new Dictionary<PossibleTasks, Func<bool>>
            {
                {PossibleTasks.GenerateKey,              tasks.GenerateKeyTask},
                {PossibleTasks.Scanner,                  tasks.ScannerTask},
                {PossibleTasks.Export,                   tasks.ExportTask},
                {PossibleTasks.Carto,                    tasks.CartoTask},
                //{PossibleTasks.Bot,                      tasks.BotTask},
                {PossibleTasks.ADHealthCheck,            tasks.AnalysisTask<HealthcheckData>},
                {PossibleTasks.ADConso,                  tasks.ConsolidationTask<HealthcheckData>},
                {PossibleTasks.HCRules,                  tasks.HealthCheckRulesTask},
                {PossibleTasks.Regen,                    tasks.RegenerateHtmlTask},
                {PossibleTasks.Reload,                   tasks.ReloadXmlReport},
                {PossibleTasks.DemoReport,               tasks.GenerateDemoReportTask},
                {PossibleTasks.UploadAllRports,          tasks.UploadAllReportInCurrentDirectory},
                {PossibleTasks.FakeReport,               tasks.GenerateFakeReport},
                {PossibleTasks.CloudHealthCheck,         tasks.AnalyzeTask},
                {PossibleTasks.ExportRulesXml,           tasks.GenerateRuleList},
            };

            requiredSettings = new Dictionary<PossibleTasks, string[]>
            {
                {PossibleTasks.ADHealthCheck,                  new string[] {"Server"}},
                {PossibleTasks.ADConso,                  new string[] {"Directory"}},
                //{PossibleTasks.Scanner,                  new string[] {"Server"}},
                //{PossibleTasks.Export,                  new string[] {"Server"}},
                {PossibleTasks.Carto,                  new string[] {"Server"}},
                {PossibleTasks.Regen,                  new string[] {"File"}},
                {PossibleTasks.Reload,                  new string[] {"File"}},
                {PossibleTasks.UploadAllRports,                  new string[] {"Directory"}},
                {PossibleTasks.FakeReport,                  new string[] {"Directory"}},
                {PossibleTasks.CloudHealthCheck,        new string[] {"AzureADCredential"}},
            };

            LoadCustomRules(tasks);
            ConsoleMenu.Header = @"  \==--O___      PingCastle (Version " + version.ToString(4) + @"     " + ConsoleMenu.GetBuildDateTime(Assembly.GetExecutingAssembly()) + @")
   \  / \  ¨¨>   Get Active Directory Security at 80% in 20% of the time
    \/   \ ,’    " + (license.EndTime < DateTime.MaxValue ? "End of support: " + license.EndTime.ToString("yyyy-MM-dd") : "") + @"
     O¨---O      To find out more about PingCastle, visit https://www.pingcastle.com                                              
      \ ,'       For online documentation, visit https://helpcenter.netwrix.com/category/pingcastle
       v         For support and questions:
                 -	Open-source community, visit https://github.com/netwrix/pingcastle/issues
                 -	Customers, visit https://www.netwrix.com/support.html  ";

            if (!ParseCommandLine(args))
                return;
            // Trace to file or console may be enabled here
            Trace.WriteLine("[New run]" + DateTime.Now.ToString("u"));
            Trace.WriteLine("PingCastle version " + version.ToString(4));
            Trace.WriteLine("Running on dotnet:" + Environment.Version);
            if (!String.IsNullOrEmpty(license.DomainLimitation) && !Tasks.compareStringWithWildcard(license.DomainLimitation, settings.Server))
            {
                WriteInRed("Limitations applies to the --server argument (" + license.DomainLimitation + ")");
                return;
            }
            if (!String.IsNullOrEmpty(license.CustomerNotice))
            {
                Console.WriteLine(license.CustomerNotice);
            }


            if (!settings.CheckArgs())
                return;

            foreach (var a in requestedActions)
            {
                var r = actions[a].Invoke();
                if (!r) return;
            }
            tasks.CompleteTasks();
        }


        private void LoadCustomRules(Tasks tasks)
        {
            if (string.IsNullOrEmpty(tasks.License.Edition))
                return;
            if (string.Equals(tasks.License.Edition, "Auditor", StringComparison.OrdinalIgnoreCase))
                return;
            if (string.Equals(tasks.License.Edition, "Basic", StringComparison.OrdinalIgnoreCase))
                return;
            PingCastle.Rules.RuleSet<HealthcheckData>.LoadCustomRules();
        }

        const string basicEditionLicense = "PC2H4sIAAAAAAAEAGNkYGDgAGKGhqddLpPuMDIDmSVA7MZQxJAKhAoMrgwpDJlAsUyGfIY8ID+fIQ1IBgD5eQzpDM4MiQzFQNkcsFpjBj0wNgCydYHYD6i6BEinAekiIJ0MpHOBMBXISwaakAjUp8BQCjQBpBvsDCBO0/5r9LZOXyzWeNPMG1smHuJw0Ov0zrFRb6kzr5szxTHoqMPxhd+ymjT93k4wtr0ee4H117lTjDwZx+aevZNQsbFQzPWVseOMtvBF/63Zbu0L0ktZd1DF1/NC7NUzX7mTDsjZLLyRLVq4nX+iPhOLqPCuknQr0fiPpgtiVrhNcthX/6yjfDMAJAREbhQBAAA=";
        string _serialNumber;
        public string GetSerialNumber()
        {
            if (String.IsNullOrEmpty(_serialNumber))
            {
                // try to load it from the configuration file
                try
                {
                    _serialNumber = ADHealthCheckingLicenseSettings.Settings.License;
                }
                catch (Exception ex)
                {
                    Trace.WriteLine("Exception when getting the license string");
                    Trace.WriteLine(ex.Message);
                    Trace.WriteLine(ex.StackTrace);
                    if (ex.InnerException != null)
                    {
                        Trace.WriteLine(ex.InnerException.Message);
                        Trace.WriteLine(ex.InnerException.StackTrace);
                    }

                }
                if (!String.IsNullOrEmpty(_serialNumber))
                {
                    Trace.WriteLine("Using the license defined in the config file");
                    try
                    {
                        var license = new ADHealthCheckingLicense(_serialNumber);
                        return _serialNumber;
                    }
                    catch (Exception ex)
                    {
                        _serialNumber = null;
                        Trace.WriteLine("Exception when verifying the external license");
                        Trace.WriteLine(ex.Message);
                        Trace.WriteLine(ex.StackTrace);
                        if (ex.InnerException != null)
                        {
                            Trace.WriteLine(ex.InnerException.Message);
                            Trace.WriteLine(ex.InnerException.StackTrace);
                        }
                    }

                }
            }
            // fault back to the default license:
            Trace.WriteLine("Using the license inside the product");
            _serialNumber = basicEditionLicense;
            try
            {
                var license = new ADHealthCheckingLicense(_serialNumber);
            }
            catch (Exception)
            {
                throw new PingCastleException("Unable to load the license from the .config file and the license embedded in PingCastle is not valid. Check that all files have been copied in the same directory and that you have a valid license");
            }
            return _serialNumber;
        }

        private void WriteInRed(string data)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(data);
            Trace.WriteLine("[Red]" + data);
            Console.ResetColor();
        }

        // parse command line arguments
        private bool ParseCommandLine(string[] args)
        {
            bool delayedInteractiveMode = false;
            if (args.Length == 0)
            {
                if (!RunInteractiveMode())
                    return false;
            }
            else
            {
                Trace.WriteLine("Before parsing arguments");
                for (int i = 0; i < args.Length; i++)
                {
                    switch (args[i])
                    {
                        case "--api-endpoint":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --api-endpoint is mandatory");
                                return false;
                            }
                            settings.apiEndpoint = args[++i];
                            {
                                Uri res;
                                if (!Uri.TryCreate(settings.apiEndpoint, UriKind.Absolute, out res))
                                {
                                    WriteInRed("unable to convert api-endpoint into an URI");
                                    return false;
                                }
                            }
                            break;
                        case "--api-key":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --api-key is mandatory");
                                return false;
                            }
                            settings.apiKey = args[++i];
                            break;
                        case "--azuread":
                            requestedActions.Add(PossibleTasks.CloudHealthCheck);
                            break;
                        case "--bot":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --bot is mandatory");
                                return false;
                            }
                            settings.botPipe = args[++i];
                            requestedActions.Add(PossibleTasks.Bot);
                            break;
                        case "--carto":
                            requestedActions.Add(PossibleTasks.Carto);
                            break;
                        case "--clientid":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --clientid is mandatory");
                                return false;
                            }
                            settings.clientid = args[++i];
                            break;
                        case "--center-on":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --center-on is mandatory");
                                return false;
                            }
                            settings.CenterDomainForSimpliedGraph = args[++i];
                            break;
                        case "--datefile":
                            HealthcheckData.UseDateInFileName();
                            break;
                        case "--debug-license":
                            break;
                        case "--demo-reports":
                            requestedActions.Add(PossibleTasks.DemoReport);
                            break;
                        case "--doNotTestSMBv1":
                            SmbScanner.DoNotTestSMBv1 = true;
                            break;
                        case "--encrypt":
                            settings.EncryptReport = true;
                            break;
                        case "--export-rules":
                            requestedActions.Add(PossibleTasks.ExportRulesXml);
                            break;
                        case "--foreigndomain":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --foreigndomain is mandatory");
                                return false;
                            }
                            ForeignUsersScanner.EnumInboundSid = args[++i];
                            break;
                        case "--explore-trust":
                            settings.ExploreTerminalDomains = true;
                            break;
                        case "--explore-forest-trust":
                            settings.ExploreForestTrust = true;
                            break;
                        case "--explore-exception":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --explore-exception is mandatory");
                                return false;
                            }
                            settings.DomainToNotExplore = new List<string>(args[++i].Split(','));
                            break;
                        case "--export":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --export is mandatory");
                                return false;
                            }
                            {
                                var exports = PingCastleFactory.GetAllExport();
                                string exportname = args[++i];
                                if (!exports.ContainsKey(exportname))
                                {
                                    string list = null;
                                    var allexports = new List<string>(exports.Keys);
                                    allexports.Sort();
                                    foreach (string name in allexports)
                                    {
                                        if (list != null)
                                            list += ",";
                                        list += name;
                                    }
                                    WriteInRed("Unsupported exportname - available scanners are:" + list);

                                }
                                settings.Export = exports[exportname];
                                requestedActions.Add(PossibleTasks.Export);
                            }
                            break;
                        case "--filter-date":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --filter-date is mandatory");
                                return false;
                            }
                            DateTime date;
                            if (!DateTime.TryParse(args[++i], out date))
                            {
                                WriteInRed("Unable to parse the date \"" + args[i] + "\" - try entering 2016-01-01");
                                return false;
                            }
                            settings.FilterReportDate = date;
                            break;
                        case "--regen-report":
                            requestedActions.Add(PossibleTasks.Regen);
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --regen-report is mandatory");
                                return false;
                            }
                            settings.InputFile = args[++i];
                            break;
                        case "--generate-fake-reports":
                            requestedActions.Add(PossibleTasks.FakeReport);
                            break;
                        case "--generate-key":
                            requestedActions.Add(PossibleTasks.GenerateKey);
                            break;
                        case "--healthcheck":
                            requestedActions.Add(PossibleTasks.ADHealthCheck);
                            break;
                        case "--hc-conso":
                            requestedActions.Add(PossibleTasks.ADConso);
                            break;
                        case "--help":
                            DisplayHelp();
                            return false;
                        case "--I-swear-I-paid-win7-support":
                            //Healthcheck.Rules.HeatlcheckRuleStaledObsoleteWin7.IPaidSupport = true;
                            Console.WriteLine("Sorry Extended support for Win7 is not available anymmore.\n--I-swear-I-paid-win7-support is ignored");
                            break;
                        case "--I-swear-I-paid-win8-support":
                            Healthcheck.Rules.HeatlcheckRuleStaledObsoleteWin8.IPaidSupportWin8 = true;
                            break;
                        case "--I-swear-I-paid-win2012-support":
                            Healthcheck.Rules.HeatlcheckRuleStaledObsolete2012.IPaidSupportWin2012 = true;
                            break;
                        case "--interactive":
                            delayedInteractiveMode = true;
                            break;
                        case "--level":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --level is mandatory");
                                return false;
                            }
                            try
                            {
                                tasks.ExportLevel = (PingCastleReportDataExportLevel)Enum.Parse(typeof(PingCastleReportDataExportLevel), args[++i]);
                            }
                            catch (Exception)
                            {
                                WriteInRed("Unable to parse the level [" + args[i] + "] to one of the predefined value (" + String.Join(",", Enum.GetNames(typeof(PingCastleReportDataExportLevel))) + ")");
                                return false;
                            }
                            break;
                        case "--license":
                            i++;
                            break;
                        case "--log":
                            Tasks.EnableLogFile();
                            break;
                        case "--log-console":
                            EnableLogConsole();
                            break;
                        case "--log-samba":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for -log-samba is mandatory");
                                return false;
                            }
                            LinuxSidResolver.LogLevel = args[++i];
                            break;
                        case "--max-nodes":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --max-nodes is mandatory");
                                return false;
                            }
                            {
                                int maxNodes;
                                if (!int.TryParse(args[++i], out maxNodes))
                                {
                                    WriteInRed("argument for --max-nodes is not a valid value (typically: 1000)");
                                    return false;
                                }
                                ReportGenerator.MaxNodes = maxNodes;
                            }
                            break;
                        case "--max-depth":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --max-depth is mandatory");
                                return false;
                            }
                            {
                                int maxDepth;
                                if (!int.TryParse(args[++i], out maxDepth))
                                {
                                    WriteInRed("argument for --max-depth is not a valid value (typically: 30)");
                                    return false;
                                }
                                ReportGenerator.MaxDepth = maxDepth;
                            }
                            break;
                        case "--no-enum-limit":
                            ReportHealthCheckSingle.MaxNumberUsersInHtmlReport = int.MaxValue;
                            break;
                        case "--no-csp-header":
                            ReportBase.NoCspHeader = true;
                            break;
                        case "--node":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --node is mandatory");
                                return false;
                            }
                            tasks.NodesToInvestigate = new List<string>(Regex.Split(args[++i], @"(?<!(?<!\\)*\\)\,"));
                            break;
                        case "--nodes":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --nodes is mandatory");
                                return false;
                            }
                            tasks.NodesToInvestigate = new List<string>(File.ReadAllLines(args[++i]));
                            break;
                        case "--notifyMail":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --notifyMail is mandatory");
                                return false;
                            }
                            settings.mailNotification = args[++i];
                            break;
                        case "--nslimit":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --nslimit is mandatory");
                                return false;
                            }
                            if (!int.TryParse(args[++i], out NullSessionScanner.NullSessionEnumerationLimit))
                            {
                                WriteInRed("argument for --nslimit is not a valid value (typically: 5)");
                                return false;
                            }
                            break;
                        case "--out":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --out is mandatory");
                                return false;
                            }
                            i++;
                            // argument processed at the beginning of the program
                            break;
                        case "--pagesize":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --pagesize is mandatory");
                                return false;
                            }
                            if (!int.TryParse(args[++i], out LDAPConnection.PageSize))
                            {
                                WriteInRed("argument for --pagesize is not a valid value (typically: 500)");
                                return false;
                            }
                            break;
                        case "--p12-file":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --p12-file is mandatory");
                                return false;
                            }
                            settings.p12file = args[++i];
                            break;
                        case "--p12-pass":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --p12-pass is mandatory");
                                return false;
                            }
                            settings.p12passSet = true;
                            settings.p12pass = args[++i];
                            break;
                        case "--password":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --password is mandatory");
                                return false;
                            }
                            var p = args[++i];
                            settings.Password = new System.Security.SecureString();
                            foreach (var c in p.ToCharArray())
                                settings.Password.AppendChar(c);
                            break;
                        case "--port":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --port is mandatory");
                                return false;
                            }
                            int port;
                            if (!int.TryParse(args[++i], out port))
                            {
                                WriteInRed("argument for --port is not a valid value (typically: 9389)");
                                return false;
                            }
                            settings.Port = port;
                            break;
                        case "--private-key":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --private-key is mandatory");
                                return false;
                            }
                            settings.privateKey = args[++i];
                            break;
                        case "--protocol":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --protocol is mandatory");
                                return false;
                            }
                            try
                            {
                                ADWebService.ConnectionType = (ADConnectionType)Enum.Parse(typeof(ADConnectionType), args[++i]);
                            }
                            catch (Exception ex)
                            {
                                Trace.WriteLine(ex.Message);
                                WriteInRed("Unable to parse the protocol [" + args[i] + "] to one of the predefined value (" + String.Join(",", Enum.GetNames(typeof(ADConnectionType))) + ")");
                                return false;
                            }
                            break;
                        case "--quota":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --quota is mandatory");
                                return false;
                            }
                            {
                                int quota;
                                if (!int.TryParse(args[++i], out quota))
                                {
                                    WriteInRed("argument for --quota is not a valid value (typically: 500)");
                                    return false;
                                }
                                ADConnection.RecordPerSeconds = quota;
                            }
                            break;
                        case "--reachable":
                            settings.AnalyzeReachableDomains = true;
                            break;
                        case "--rules":
                            requestedActions.Add(PossibleTasks.HCRules);
                            break;
                        case "--scanner":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --scanner is mandatory");
                                return false;
                            }
                            {
                                var scanners = PingCastleFactory.GetAllScanners();
                                string scannername = args[++i];
                                if (!scanners.ContainsKey(scannername))
                                {
                                    string list = null;
                                    var allscanners = new List<string>(scanners.Keys);
                                    allscanners.Sort();
                                    foreach (string name in allscanners)
                                    {
                                        if (list != null)
                                            list += ",";
                                        list += name;
                                    }
                                    WriteInRed("Unsupported scannername - available scanners are:" + list);
                                    return false;
                                }
                                settings.Scanner = scanners[scannername];
                                requestedActions.Add(PossibleTasks.Scanner);
                            }
                            break;
                        case "--scmode-all":
                            ScannerBase.ScanningMode = 1;
                            break;
                        case "--scmode-single":
                            ScannerBase.ScanningMode = 2;
                            break;
                        case "--scmode-workstation":
                            ScannerBase.ScanningMode = 3;
                            break;
                        case "--scmode-server":
                            ScannerBase.ScanningMode = 4;
                            break;
                        case "--scmode-dc":
                            ScannerBase.ScanningMode = 5;
                            break;
                        case "--scmode-file":
                            ScannerBase.ScanningMode = 6;
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --scmode-file is mandatory");
                                return false;
                            }
                            settings.InputFile = args[++i];
                            break;
                        case "--sendxmlTo":
                        case "--sendXmlTo":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --sendXmlTo is mandatory");
                                return false;
                            }
                            settings.sendXmlTo = args[++i];
                            break;
                        case "--sendhtmlto":
                        case "--sendHtmlTo":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --sendHtmlTo is mandatory");
                                return false;
                            }
                            settings.sendHtmlTo = args[++i];
                            break;
                        case "--sendallto":
                        case "--sendAllTo":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --sendAllTo is mandatory");
                                return false;
                            }
                            settings.sendAllTo = args[++i];
                            break;
                        case "--server":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --server is mandatory");
                                return false;
                            }
                            settings.Server = args[++i];
                            break;
                        case "--skip-null-session":
                            HealthcheckAnalyzer.SkipNullSession = true;
                            break;
                        case "--skip-dc-rpc":
                            HealthcheckAnalyzer.SkipRPC = true;
                            break;
                        case "--reload-report":
                        case "--slim-report":
                            requestedActions.Add(PossibleTasks.Reload);
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --slim-report is mandatory");
                                return false;
                            }
                            settings.InputFile = args[++i];
                            break;
                        case "--smtplogin":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --smtplogin is mandatory");
                                return false;
                            }
                            settings.smtpLogin = args[++i];
                            break;
                        case "--smtppass":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --smtppass is mandatory");
                                return false;
                            }
                            settings.smtpPassword = args[++i];
                            break;
                        case "--smtptls":
                            settings.smtpTls = true;
                            break;
                        case "--tenantid":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --tenantid is mandatory");
                                return false;
                            }
                            settings.tenantid = args[++i];
                            break;
                        case "--thumbprint":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --thumbprint is mandatory");
                                return false;
                            }
                            settings.thumbprint = args[++i];
                            break;
                        case "--upload-all-reports":
                            requestedActions.Add(PossibleTasks.UploadAllRports);
                            break;
                        case "--user":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --user is mandatory");
                                return false;
                            }
                            i++;
                            if (args[i].Contains("\\"))
                            {
                                int pos = args[i].IndexOf('\\');
                                settings.Userdomain = args[i].Substring(0, pos);
                                settings.User = args[i].Substring(pos + 1);
                            }
                            else
                            {
                                settings.User = args[i];
                                if (!settings.User.Contains("@"))
                                {
                                    Console.ForegroundColor = ConsoleColor.Yellow;
                                    Console.WriteLine("Beware: the user is not on the form domain\\user or user@domain.com. Most likely the GPO part will trigger an access denied error.");
                                    Console.ResetColor();
                                }
                            }
                            break;
                        case "--use-prt":
                            settings.usePrt = true;
                            break;
                        case "--webdirectory":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --webdirectory is mandatory");
                                return false;
                            }
                            settings.sharepointdirectory = args[++i];
                            break;
                        case "--webuser":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --webuser is mandatory");
                                return false;
                            }
                            settings.sharepointuser = args[++i];
                            break;
                        case "--webpassword":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --webpassword is mandatory");
                                return false;
                            }
                            settings.sharepointpassword = args[++i];
                            break;
                        case "--xmls":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --xmls is mandatory");
                                return false;
                            }
                            settings.InputDirectory = args[++i];
                            break;
                        default:
                            WriteInRed("unknow argument: " + args[i]);
                            DisplayHelp();
                            return false;
                    }
                }
                Trace.WriteLine("After parsing arguments");
            }
            if (requestedActions.Count == 0 && !delayedInteractiveMode)
            {
                WriteInRed("You must choose at least one value among --healthcheck --azuread --hc-conso --advanced-export --advanced-report --nullsession --carto");
                DisplayHelp();
                return false;
            }
            Trace.WriteLine("Things to do OK");
            if (delayedInteractiveMode)
            {
                RunInteractiveMode();
            }
            foreach (var action in requestedActions)
            {
                if (requiredSettings.ContainsKey(action))
                {
                    var r = requiredSettings[action];
                    if (r.Length > 0)
                    {
                        var state = settings.EnsureDataCompleted(r);
                        if (state != DisplayState.Run)
                        {
                            DisplayHelp();
                            return false;
                        }
                    }
                }
            }
            return true;
        }

        private void EnableLogConsole()
        {
            Trace.AutoFlush = true;
            TextWriterTraceListener listener = new TextWriterTraceListener(Console.Out);
            Trace.Listeners.Add(listener);
        }

        // interactive interface
        private bool RunInteractiveMode()
        {
            settings.InteractiveMode = true;
            Stack<DisplayState> states = new Stack<DisplayState>();
            var state = DisplayState.MainMenu;

            states.Push(state);
            while (states.Count > 0 && states.Peek() != DisplayState.Run)
            {
                switch (state)
                {
                    case DisplayState.MainMenu:
                        state = DisplayMainMenu();
                        break;
                    case DisplayState.ScannerMenu:
                        state = settings.DisplayScannerMenu();
                        break;
                    case DisplayState.AvancedMenu:
                        state = DisplayAdvancedMenu();
                        break;
                    case DisplayState.ProtocolMenu:
                        state = DisplayProtocolMenu();
                        break;
                    case DisplayState.ExportMenu:
                        state = settings.DisplayExportMenu();
                        break;
                    default:
                        // defensive programming
                        if (state != DisplayState.Exit)
                        {
                            Console.WriteLine("No implementation of state " + state);
                            state = DisplayState.Exit;
                        }
                        break;
                }
                if (state == DisplayState.Exit)
                {
                    states.Pop();
                    if (states.Count > 0)
                        state = states.Peek();
                }
                else
                {
                    states.Push(state);
                }
            }
            return (states.Count > 0);
        }

        DisplayState DisplayMainMenu()
        {
            requestedActions.Clear();

            List<ConsoleMenuItem> choices = new List<ConsoleMenuItem>() {
                new ConsoleMenuItem("healthcheck","Score the risk of a domain", "This is the main functionnality of PingCastle. In a matter of minutes, it produces a report which will give you an overview of your Active Directory security. This report can be generated on other domains by using the existing trust links."),
                new ConsoleMenuItem("azuread","Score the risk of AzureAD", "This is the main functionnality of PingCastle. In a matter of minutes, it produces a report which will give you an overview of your AzureAD security."),
                new ConsoleMenuItem("conso","Aggregate multiple reports into a single one", "With many healthcheck reports, you can get a single report for a whole scope. Maps will be generated."),
                new ConsoleMenuItem("carto","Build a map of all interconnected domains", "It combines the healthcheck reports that would be run on all trusted domains and then the conso option. But lighter and then faster."),
                new ConsoleMenuItem("scanner","Perform specific security checks on workstations", "You can know your local admins, if Bitlocker is properly configured, discover unprotect shares, ... A menu will be shown to select the right scanner."),
                new ConsoleMenuItem("export","Export users or computers", "Don't involve your admin and get the list of users or computers you want to get. A menu will be shown to select the export."),
                new ConsoleMenuItem("advanced","Open the advanced menu", "This is the place you want to configure PingCastle without playing with command line switches."),
            };

            ConsoleMenu.Title = "What do you want to do?";
            ConsoleMenu.Information = "Using interactive mode.\r\nDo not forget that there are other command line switches like --help that you can use";
            int choice = ConsoleMenu.SelectMenu(choices);
            if (choice == 0)
                return DisplayState.Exit;

            string whattodo = choices[choice - 1].Choice;
            switch (whattodo)
            {
                default:
                case "healthcheck":
                    requestedActions.Add(PossibleTasks.ADHealthCheck);
                    return DisplayState.Run;
                case "azuread":
                    requestedActions.Add(PossibleTasks.CloudHealthCheck);
                    return DisplayState.Run;
                case "carto":
                    requestedActions.Add(PossibleTasks.Carto);
                    return DisplayState.Run;
                case "conso":
                    requestedActions.Add(PossibleTasks.ADConso);
                    return DisplayState.Run;
                case "scanner":
                    requestedActions.Add(PossibleTasks.Scanner);
                    return DisplayState.ScannerMenu;
                case "export":
                    requestedActions.Add(PossibleTasks.Export);
                    return DisplayState.ExportMenu;
                case "advanced":
                    return DisplayState.AvancedMenu;
            }
        }

        DisplayState DisplayAdvancedMenu()
        {
            List<ConsoleMenuItem> choices = new List<ConsoleMenuItem>() {
                new ConsoleMenuItem("protocol","Change the protocol used to query the AD (LDAP, ADWS, ...)"),
                new ConsoleMenuItem("hcrules","Generate a report containing all rules applied by PingCastle"),
                new ConsoleMenuItem("generatekey","Generate RSA keys used to encrypt and decrypt reports"),
                new ConsoleMenuItem("noenumlimit","Remove the 100 items limitation in healthcheck reports"),
                new ConsoleMenuItem("decrypt","Decrypt a xml report"),
                new ConsoleMenuItem("regenerate","Regenerate the html report based on the xml report"),
                new ConsoleMenuItem("log","Enable logging (log is " + (Trace.Listeners.Count > 1 ? "enabled":"disabled") + ")"),
            };

            ConsoleMenu.Title = "What do you want to do?";
            int choice = ConsoleMenu.SelectMenu(choices);
            if (choice == 0)
                return DisplayState.Exit;

            string whattodo = choices[choice - 1].Choice;
            switch (whattodo)
            {
                default:
                case "protocol":
                    return DisplayState.ProtocolMenu;
                case "hcrules":
                    requestedActions.Add(PossibleTasks.HCRules);
                    return DisplayState.Run;
                case "generatekey":
                    requestedActions.Add(PossibleTasks.GenerateKey);
                    return DisplayState.Run;
                case "decrypt":
                    requestedActions.Add(PossibleTasks.Reload);
                    return DisplayState.Run;
                case "regenerate":
                    requestedActions.Add(PossibleTasks.Regen);
                    return DisplayState.Run;
                case "log":
                    if (Trace.Listeners.Count <= 1)
                        Tasks.EnableLogFile();
                    return DisplayState.Exit;
                case "noenumlimit":
                    ReportHealthCheckSingle.MaxNumberUsersInHtmlReport = int.MaxValue;
                    ConsoleMenu.Notice = "Limitation removed";
                    return DisplayState.Exit;
            }
        }

        DisplayState DisplayProtocolMenu()
        {
            List<ConsoleMenuItem> choices = new List<ConsoleMenuItem>() {
                new ConsoleMenuItem("ADWSThenLDAP","default: ADWS then if failed, LDAP"),
                new ConsoleMenuItem("ADWSOnly","use only ADWS"),
                new ConsoleMenuItem("LDAPOnly","use only LDAP"),
                new ConsoleMenuItem("LDAPThenADWS","LDAP then if failed, ADWS"),
            };

            ConsoleMenu.Title = "What protocol do you want to use?";
            ConsoleMenu.Information = "ADWS (Active Directory Web Service - tcp/9389) is the fastest protocol but is limited 5 sessions in parallele and a 30 minutes windows. LDAP is more stable but slower.\r\nCurrent protocol: [" + ADWebService.ConnectionType + "]";
            int defaultChoice = 1;
            for (int i = 0; i < choices.Count; i++)
            {
                if (choices[i].Choice == ADWebService.ConnectionType.ToString())
                    defaultChoice = 1 + i;
            }
            int choice = ConsoleMenu.SelectMenu(choices, defaultChoice);
            if (choice == 0)
                return DisplayState.Exit;

            string whattodo = choices[choice - 1].Choice;
            ADWebService.ConnectionType = (ADConnectionType)Enum.Parse(typeof(ADConnectionType), whattodo);
            return DisplayState.Exit;
        }


        private static void DisplayHelp()
        {
            Console.WriteLine("switch:");
            Console.WriteLine("  --help              : display this message");
            Console.WriteLine("  --interactive       : force the interactive mode");
            Console.WriteLine("  --log               : generate a log file");
            Console.WriteLine("  --log-console       : add log to the console");
            Console.WriteLine("  --log-samba <option>: enable samba login (example: 10)");
            Console.WriteLine("  --api-endpoint <>   : to upload report via api call eg: http://server");
            Console.WriteLine("  --api-key  <key>    : and using the api key as registered");
            Console.WriteLine("");
            Console.WriteLine("Common options when connecting to the AD");
            Console.WriteLine("  --server <server>   : use this server (default: current domain controller)");
            Console.WriteLine("                        the special value * or *.forest do the healthcheck for all domains");
            Console.WriteLine("  --port <port>       : the port to use for ADWS or LDAP (default: 9389 or 389)");
            Console.WriteLine("  --user <user>       : use this user (default: integrated authentication)");
            Console.WriteLine("  --password <pass>   : use this password (default: asked on a secure prompt)");
            Console.WriteLine("  --protocol <proto>  : selection the protocol to use among LDAP or ADWS (fastest)");
            Console.WriteLine("                      : ADWSThenLDAP (default), ADWSOnly, LDAPOnly, LDAPThenADWS");
            Console.WriteLine("  --pagesize <size>   : change the default LDAP page size - default is 500");
            Console.WriteLine("  --quota <num>       : Number of LDAP items per second that will be processed - default unlimited");
            Console.WriteLine("");
            Console.WriteLine("  --carto             : perform a quick cartography with domains surrounding");
            Console.WriteLine("");
            Console.WriteLine("  --healthcheck       : perform the healthcheck (step1)");
            Console.WriteLine("    --explore-trust   : on domains of a forest, after the healthcheck, do the hc on all trusted domains except domains of the forest and forest trusts");
            Console.WriteLine("    --explore-forest-trust : on root domain of a forest, after the healthcheck, do the hc on all forest trusts discovered");
            Console.WriteLine("    --explore-trust and --explore-forest-trust can be run together");
            Console.WriteLine("    --explore-exception <domains> : comma separated values of domains that will not be explored automatically");
            Console.WriteLine("");
            Console.WriteLine("    --datefile        : insert the date into the report filename");
            Console.WriteLine("    --encrypt         : use an RSA key stored in the .config file to crypt the content of the xml report");
            Console.WriteLine("    --level <level>   : specify the amount of data found in the xml file");
            Console.WriteLine("                      : level: Full, Normal, Light");
            Console.WriteLine("    --no-enum-limit   : remove the max 100 users limitation in html report");
            Console.WriteLine("    --reachable       : add reachable domains to the list of discovered domains");
            Console.WriteLine("    --sendXmlTo <emails>: send xml reports to a mailbox (comma separated email)");
            Console.WriteLine("    --sendHtmlTo <emails>: send html reports to a mailbox");
            Console.WriteLine("    --sendAllTo <emails>: send html reports to a mailbox");
            Console.WriteLine("    --notifyMail <emails>: add email notification when the mail is received");
            Console.WriteLine("    --smtplogin <user>: allow smtp credentials ...");
            Console.WriteLine("    --smtppass <pass> : ... to be entered on the command line");
            Console.WriteLine("    --smtptls         : enable TLS/SSL in SMTP if used on other port than 465 and 587");
            Console.WriteLine("    --skip-null-session: do not test for null session");
            Console.WriteLine("    --skip-dc-rpc     : do not test for rpc on DC");
            Console.WriteLine("    --webdirectory <dir>: upload the xml report to a webdav server");
            Console.WriteLine("    --webuser <user>  : optional user and password");
            Console.WriteLine("    --webpassword <password>");
            Console.WriteLine("    --max-depth       : maximum number of relation to explore (default:30)");
            Console.WriteLine("    --max-nodes       : maximum number of node to include (default:1000)");
            Console.WriteLine("    --node <node>     : create a report based on a object");
            Console.WriteLine("                      : example: \"cn=name\" or \"name\"");
            Console.WriteLine("    --nodes <file>    : create x report based on the nodes listed on a file");
            Console.WriteLine("");
            Console.WriteLine("    --I-swear-I-paid-win7-support : meaningless");
            Console.WriteLine("    --I-swear-I-paid-win8-support : meaningless");
            Console.WriteLine("    --I-swear-I-paid-win2012-support : meaningless");
            Console.WriteLine("");
            Console.WriteLine("--rules               : Generate an html containing all the rules used by PingCastle");
            Console.WriteLine("");
            Console.WriteLine("  --generate-key      : generate and display a new RSA key for encryption");
            Console.WriteLine("");
            Console.WriteLine("  --no-csp-header     : disable the Content Security Policy header. More risks but enables styles & js when stored on a webserver");
            Console.WriteLine("");
            Console.WriteLine("  --hc-conso          : consolidate multiple healthcheck xml reports (step2)");
            Console.WriteLine("    --center-on <domain> : center the simplified graph on this domain");
            Console.WriteLine("                         default is the domain with the most links");
            Console.WriteLine("    --xmls <path>     : specify the path containing xml (default: current directory)");
            Console.WriteLine("    --filter-date <date>: filter report generated after the date.");
            Console.WriteLine("");
            Console.WriteLine("  --regen-report <xml> : regenerate a html report based on a xml report");
            Console.WriteLine("  --reload-report <xml> : regenerate a xml report based on a xml report");
            Console.WriteLine("                          any healthcheck switches (send email, ..) can be reused");
            Console.WriteLine("    --level <level>   : specify the amount of data found in the xml file");
            Console.WriteLine("                      : level: Full, Normal, Light (default: Normal)");
            Console.WriteLine("    --encrypt         : use an RSA key stored in the .config file to crypt the content of the xml report");
            Console.WriteLine("                        the absence of this switch on an encrypted report will produce a decrypted report");
            Console.WriteLine("");
            Console.WriteLine("  --scanner <type>    : perform a scan on one of all computers of the domain (using --server)");
            Console.WriteLine("");
            
            var scanner = PingCastleFactory.GetAllScanners();
            var scannerNames = new List<string>(scanner.Keys);
            scannerNames.Sort();
            foreach (var scannerName in scannerNames)
            {
                Type scannerType = scanner[scannerName];
                IScanner iscanner = PingCastleFactory.LoadScanner(scannerType);
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine(iscanner.Name);
                Console.ResetColor();
                Console.WriteLine(iscanner.Description);
            }
            Console.WriteLine("  options for scanners:");
            Console.WriteLine("    --scmode-all      : scan all computers (default)");
            Console.WriteLine("    --scmode-single   : force scanner to check one single computer");
            Console.WriteLine("    --scmode-workstation : force scanner to check workstations");
            Console.WriteLine("    --scmode-server   : force scanner to check servers");
            Console.WriteLine("    --scmode-dc       : force scanner to check dc");
            Console.WriteLine("    --scmode-file <file> : force scanner to use the computer from file");
            Console.WriteLine("    --nslimit <number>: Limit the number of users to enumerate (default: unlimited)");
            Console.WriteLine("    --foreigndomain <sid> : foreign domain targeted using its FQDN or sids");
            Console.WriteLine("                        Example of SID: S-1-5-21-4005144719-3948538632-2546531719");
            Console.WriteLine("");
            Console.WriteLine("  --export <type>    : perform an export of objects of the domain (using --server)");
            var exports = PingCastleFactory.GetAllExport();
            var exportNames = new List<string>(exports.Keys);
            exportNames.Sort();
            foreach (var exportName in exportNames)
            {
                Type exportType = exports[exportName];
                IExport iexport = PingCastleFactory.LoadExport(exportType);
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine(iexport.Name);
                Console.ResetColor();
                Console.WriteLine(iexport.Description);
            }
            Console.WriteLine("");
            Console.WriteLine("Common options when connecting to AzureAD");
            Console.WriteLine("     --tenantid xx: specify the tenant id to use. Requiered for cert auth");
            Console.WriteLine("Authentication");
            Console.WriteLine("  --use-prt          : use prt to log on");
            Console.WriteLine("");
            Console.WriteLine("Certificate authentication");
            Console.WriteLine("   --clientid xxx : specify the client id to which the certificate is associated");
            Console.WriteLine("   With private key");
            Console.WriteLine("     --thumbprint xxx : specify the thumprint of the certificate configured");
            Console.WriteLine("     --private-key xxx : specify the key file to use (PKCS8)");
            Console.WriteLine("");
            Console.WriteLine("   With P12");
            Console.WriteLine("     --p12-file xxx : specify the P12 file to use");
            Console.WriteLine("     --p12-pass xxx : specify the password to use");
            Console.WriteLine("");
            Console.WriteLine("  --upload-all-reports: use the API to upload all reports in the current directory");
            Console.WriteLine("    --api-endpoint <> : upload report via api call eg: http://server");
            Console.WriteLine("    --api-key  <key>  : and using the api key as registered");
            Console.WriteLine("                        Note: do not forget to set --level Full to send all the information available");
            Console.WriteLine("");
            Console.WriteLine("  --export-rules : export all rule in a single xml file");


        }
    }


}


