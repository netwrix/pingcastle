//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.ADWS;
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
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using System.Security.Principal;

namespace PingCastle
{
    [LicenseProvider(typeof(PingCastle.ADHealthCheckingLicenseProvider))]
    public class Program : IPingCastleLicenseInfo
    {
        bool PerformHealthCheckReport = false;
        bool PerformHealthCheckConsolidation = false;
        bool PerformNullSession = false;
		bool PerformNullTrusts = false;
        bool PerformGenerateKey = false;
        bool PerformCarto = false;
        bool PerformAdvancedLive;
        bool PerformUploadAllReport;
        private bool PerformRegenerateReport;
        private bool PerformHealthCheckReloadReport;
        bool PerformHealthCheckGenerateDemoReports;
		private bool PerformEnumInboundTrust;
		bool PerformScanner = false;
        Tasks tasks = new Tasks();
		

        static void Main(string[] args)
        {
            try
            {
                AppDomain.CurrentDomain.UnhandledException += new UnhandledExceptionEventHandler(CurrentDomain_UnhandledException);
				AppDomain.CurrentDomain.AssemblyResolve += new ResolveEventHandler(CurrentDomain_AssemblyResolve);
                Trace.WriteLine("Running on dotnet:" + Environment.Version);
                Program program = new Program();
                program.Run(args);
                if (program.tasks.InteractiveMode)
                {
                    Console.WriteLine("=============================================================================");
                    Console.WriteLine("Program launched in interactive mode - press any key to terminate the program");
                    Console.WriteLine("=============================================================================");
                    Console.ReadKey();
                }
            }
            catch (Exception ex)
            {
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
			//return Assembly.GetExecutingAssembly(); 
		}

        private void Run(string[] args)
        {
            ADHealthCheckingLicense license = null;
            Version version = Assembly.GetExecutingAssembly().GetName().Version;
            Trace.WriteLine("PingCastle version " + version.ToString(4));
            for(int i = 0; i <args.Length; i++)
            {
                if (args[i].Equals("--debug-license", StringComparison.InvariantCultureIgnoreCase))
                {
                    EnableLogConsole();
                }
                else if (args[i].Equals("--license", StringComparison.InvariantCultureIgnoreCase) && i + 1 < args.Length)
                {
                    _serialNumber = args[++i];
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
            Console.WriteLine("  |:.      PingCastle (Version " + version.ToString(4) +")");
            Console.WriteLine("  |  #:.   Get Active Directory Security at 80% in 20% of the time");
            Console.WriteLine("  # @@  >  " + (license.EndTime < DateTime.MaxValue? "End of support: " + license.EndTime.ToShortDateString() : ""));
            Console.WriteLine("  | @@@:   ");
            Console.WriteLine("  : .#                                 Vincent LE TOUX (contact@pingcastle.com)");
            Console.WriteLine("  .:                                                 https://www.pingcastle.com");
            if (!ParseCommandLine(args))
                return;
            // Trace to file or console may be enabled here
			Trace.WriteLine("[New run]" + DateTime.Now.ToString("u"));
			Trace.WriteLine("PingCastle version " + version.ToString(4));
            Trace.WriteLine("Running on dotnet:" + Environment.Version);
            if (!String.IsNullOrEmpty(license.DomainLimitation) && !Tasks.compareStringWithWildcard(license.DomainLimitation, tasks.Server))
            {
                WriteInRed("Limitations applies to the --server argument (" + license.DomainLimitation + ")");
                return;
            }
            if (!String.IsNullOrEmpty(license.CustomerNotice))
            {
                Console.WriteLine(license.CustomerNotice);
            }
            if (PerformGenerateKey)
            {
                if (!tasks.GenerateKeyTask()) return;
            }
			if (PerformScanner)
			{
				if (!tasks.ScannerTask()) return;
			}
            if (PerformNullSession)
            {
                if (!tasks.NullSessionTask()) return;
            }
			if (PerformNullTrusts)
			{
				if (!tasks.NullTrustsTask()) return;
			}
			if (PerformEnumInboundTrust)
			{
				if (!tasks.EnumInboundTrustTask()) return;
			}
            if (PerformCarto)
            {
                if (!tasks.CartoTask(PerformHealthCheckGenerateDemoReports)) return;
            }
            if (PerformHealthCheckReport)
            {
                if (!tasks.HeatlthCheckTask()) return;
            }

            if (PerformHealthCheckConsolidation || (tasks.Server == "*" && tasks.InteractiveMode))
            {
                if (!tasks.ConsolidationTask()) return;
            }
            if (PerformRegenerateReport)
            {
                if (!tasks.RegenerateHtmlTask()) return;
            }
            if (PerformHealthCheckReloadReport)
            {
                if (!tasks.ReloadXmlReport()) return;
            }
            if (PerformHealthCheckGenerateDemoReports && !PerformCarto)
            {
                if (!tasks.GenerateDemoReportTask()) return;
            }
            if (PerformAdvancedLive)
            {
                if (!tasks.AdvancedLiveAnalysisTask()) return;
            }
            if (PerformUploadAllReport)
            {
                if (!tasks.UploadAllReportInCurrentDirectory()) return;
            }
        }

        string _serialNumber;
        public string GetSerialNumber()
        {
            if (String.IsNullOrEmpty(_serialNumber))
            {
                try
                {
                    _serialNumber = ADHealthCheckingLicenseSettings.Settings.License;
                }
                catch (Exception ex)
                {
                    Trace.WriteLine("Exception when getting the license string");
                    Trace.WriteLine(ex.Message);
                    Trace.WriteLine(ex.StackTrace);
                    throw new ApplicationException("Unable to load the license from the .config file. Check that all files have been copied in the same directory");
                }
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

        private string GetCurrentDomain()
        {
            return IPGlobalProperties.GetIPGlobalProperties().DomainName;
        }

        // parse command line arguments
        private bool ParseCommandLine(string[] args)
        {
            string user = null;
            string userdomain = null;
            string password = null;
            bool delayedInteractiveMode = false;
            if (args.Length == 0)
            {
                RunInteractiveMode();
            }
            else
            {
                for (int i = 0; i < args.Length; i++)
                {
                    switch (args[i])
                    {
                        case "--adws-port":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --adws-port is mandatory");
                                return false;
                            }
                            if (!int.TryParse(args[++i], out tasks.ADWSPort))
                            {
                                WriteInRed("argument for --adws-port is not a valid value (typically: 9389)");
                                return false;
                            }
                            break;
                        case "--api-endpoint":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --api-endpoint is mandatory");
                                return false;
                            }
                            tasks.apiEndpoint = args[++i];
                            {
                                Uri res;
                                if (!Uri.TryCreate(tasks.apiEndpoint, UriKind.Absolute, out res))
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
                            tasks.apiKey = args[++i];
                            break;
                        case "--auto-reports":
                            tasks.AutoReport = true;
                            break;
                        case "--carto":
                            PerformCarto = true;
                            break;
                        case "--center-on":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --center-on is mandatory");
                                return false;
                            }
                            tasks.CenterDomainForSimpliedGraph = args[++i];
                            break;
                        case "--debug-license":
                            break;
                        case "--demo-reports":
                            PerformHealthCheckGenerateDemoReports = true;
                            break;
                        case "--encrypt":
                            tasks.EncryptReport = true;
                            break;
						case "--enuminbound":
							if (i + 1 >= args.Length)
                            {
								WriteInRed("argument for --enuminbound is mandatory");
                                return false;
                            }
							tasks.EnumInboundSid = args[++i];
							PerformEnumInboundTrust = true;
                            break;
                        case "--explore-trust":
                            tasks.ExploreTerminalDomains = true;
                            break;
                        case "--explore-forest-trust":
                            tasks.ExploreForestTrust = true;
                            break;
                        case "--explore-exception":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --explore-exception is mandatory");
                                return false;
                            }
                            tasks.DomainToNotExplore = new List<string>(args[++i].Split(','));
                            break;
                        case "--filter-date":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --filter-date is mandatory");
                                return false;
                            }
                            if (!DateTime.TryParse(args[++i], out tasks.FilterReportDate))
                            {
                                WriteInRed("Unable to parse the date \"" + args[i] + "\" - try entering 2016-01-01");
                                return false;
                            }
                            break;
						case "--regen-report":
                            PerformRegenerateReport = true;
                            if (i + 1 >= args.Length)
                            {
								WriteInRed("argument for --regen-report is mandatory");
                                return false;
                            }
                            tasks.FileOrDirectory = args[++i];
                            break;
                        case "--generate-key":
                            PerformGenerateKey = true;
                            break;
						case "--graph":
							PerformAdvancedLive = true;
							break;
                        case "--healthcheck":
                            PerformHealthCheckReport = true;
                            break;
                        case "--hc-conso":
                            PerformHealthCheckConsolidation = true;
                            break;
                        case "--help":
                            DisplayHelp();
                            return false;
                        case "--interactive":
                            delayedInteractiveMode = true;
                            break;
                        case "--json-only":
                            HealthCheckReportMapBuilder.JasonOnly = true;
                            ReportGenerator.JasonOnly = true;
                            break;
                        case "--level":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --level is mandatory");
                                return false;
                            }
                            try
                            {
                                tasks.ExportLevel = (HealthcheckDataLevel)Enum.Parse(typeof(HealthcheckDataLevel), args[++i]);
                            }
                            catch (Exception)
                            {
								WriteInRed("Unable to parse the level [" + args[i] + "] to one of the predefined value (" + String.Join(",", Enum.GetNames(typeof(HealthcheckDataLevel))) + ")");
                                return false;
                            }
                            break;
                        case "--license":
                            i++;
                            break;
                        case "--log":
                            EnableLogFile();
                            break;
                        case "--log-console":
                            EnableLogConsole();
                            break;
                        case "--max-nodes":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --max-nodes is mandatory");
                                return false;
                            }
                            if (!int.TryParse(args[++i], out tasks.MaxNodes))
                            {
                                WriteInRed("argument for --max-nodes is not a valid value (typically: 1000)");
                                return false;
                            }
                            break;
                        case "--max-depth":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --max-depth is mandatory");
                                return false;
                            }
                            if (!int.TryParse(args[++i], out tasks.MaxDepth))
                            {
                                WriteInRed("argument for --max-depth is not a valid value (typically: 30)");
                                return false;
                            }
                            break;
                        case "--no-enum-limit":
                            HealthCheckReportSingle.MaxNumberUsersInHtmlReport = int.MaxValue;
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
                            tasks.mailNotification = args[++i];
                            break;
                        case "--nslimit":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --nslimit is mandatory");
                                return false;
                            }
                            if (!int.TryParse(args[++i], out tasks.NullSessionEnumerationLimit))
                            {
                                WriteInRed("argument for --nslimit is not a valid value (typically: 5)");
                                return false;
                            }
                            break;
                        case "--nullsession":
                            PerformNullSession = true;
                            break;
						case "--nulltrusts":
							PerformNullTrusts = true;
							break;
                        case "--password":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --password is mandatory");
                                return false;
                            }
                            password = args[++i];
                            break;
                        case "--protocol":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --protocol is mandatory");
                                return false;
                            }
                            try
                            {
                                ADWebService.ConnectionType = (ADConnectionType) Enum.Parse(typeof(ADConnectionType), args[++i]);
                            }
                            catch (Exception ex)
                            {
                                Trace.WriteLine(ex.Message);
								WriteInRed("Unable to parse the protocol [" + args[i] + "] to one of the predefined value (" + String.Join(",", Enum.GetNames(typeof(ADConnectionType))) + ")"); 
                                return false;
                            }
                            break;
                        case "--reachable":
                            tasks.AnalyzeReachableDomains = true;
                            break;
                        case "--rev-direction":
                            tasks.ReverseDirection = true;
                            break;
						case "--scanner":
							if (i + 1 >= args.Length)
							{
								WriteInRed("argument for --scanner is mandatory");
								return false;
							}
							{
								var scanners = ScannerBase.GetAllScanners();
								string scannername = args[++i];
								if (!scanners.ContainsKey(scannername))
								{
									string list = null;
									foreach(string name in scanners.Keys)
									{
										if (list != null)
											list += ",";
										list += name;
									}
									WriteInRed("Unsupported scannername - list is:" + list);
								}
								tasks.Scanner = scanners[scannername];
								PerformScanner = true;
							}
							break;
                        case "--sendxmlTo":
                        case "--sendXmlTo":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --sendXmlTo is mandatory");
                                return false;
                            }
                            tasks.sendXmlTo = args[++i];
                            break;
                        case "--sendhtmlto":
                        case "--sendHtmlTo":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --sendHtmlTo is mandatory");
                                return false;
                            }
                            tasks.sendHtmlTo = args[++i];
                            break;
                        case "--sendallto":
                        case "--sendAllTo":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --sendAllTo is mandatory");
                                return false;
                            }
                            tasks.sendAllTo = args[++i];
                            break;
                        case "--server":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --server is mandatory");
                                return false;
                            }
                            tasks.Server = args[++i];
                            break;
                        case "--skip-null-session":
                            HealthcheckAnalyzer.SkipNullSession = true;
                            break;
                        case "--reload-report":
                        case "--slim-report":
                            PerformHealthCheckReloadReport = true;
                            if (i + 1 >= args.Length)
                            {
								WriteInRed("argument for --slim-report is mandatory");
                                return false;
                            }
                            tasks.FileOrDirectory = args[++i];
                            break;
                        case "--smtplogin":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --smtplogin is mandatory");
                                return false;
                            }
                            tasks.smtpLogin = args[++i];
                            break;
                        case "--smtppass":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --smtppass is mandatory");
                                return false;
                            }
                            tasks.smtpPassword = args[++i];
                            break;
                        case "--smtptls":
                            tasks.smtpTls = true;
                            break;
                        case "--split-ou":
                        case "--split-OU":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --split-OU is mandatory");
                                return false;
                            }
                            if (!int.TryParse(args[++i], out tasks.NumberOfDepthForSplit))
                            {
                                WriteInRed("argument for --split-OU is not a valid value (typically: 1,2, ..)");
                                return false;
                            }
                            break;
                        case "--upload-all-reports":
                            PerformUploadAllReport = true;
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
                                userdomain = args[i].Substring(0, pos);
                                user = args[i].Substring(pos + 1);
                            }
                            else
                            {
                                user = args[i];
                            }
                            break;
                        case "--webdirectory":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --webdirectory is mandatory");
                                return false;
                            }
                            tasks.sharepointdirectory = args[++i];
                            break;
                        case "--webuser":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --webuser is mandatory");
                                return false;
                            }
                            tasks.sharepointuser = args[++i];
                            break;
                        case "--webpassword":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --webpassword is mandatory");
                                return false;
                            }
                            tasks.sharepointpassword = args[++i];
                            break;
                        case "--xmls":
                            if (i + 1 >= args.Length)
                            {
                                WriteInRed("argument for --xmls is mandatory");
                                return false;
                            }
                            tasks.FileOrDirectory = args[++i];
                            break;
                        default:
                            WriteInRed("unknow argument: " + args[i]);
                            DisplayHelp();
                            return false;
                    }
                }
            }
            if (!PerformHealthCheckReport && !PerformHealthCheckConsolidation
                && !PerformRegenerateReport && !PerformHealthCheckReloadReport && !delayedInteractiveMode
                && !PerformNullSession && !PerformScanner
                && !PerformGenerateKey && !PerformHealthCheckGenerateDemoReports && ! PerformCarto && !PerformAdvancedLive
				&& !PerformNullTrusts  && !PerformEnumInboundTrust && !PerformUploadAllReport)
            {
                WriteInRed("You must choose at least one value among --healthcheck --hc-conso --advanced-export --advanced-report --nullsession --carto");
                DisplayHelp();
                return false;
            }
            if (delayedInteractiveMode)
            {
                RunInteractiveMode();
            }
			if (PerformHealthCheckReport || PerformScanner || PerformAdvancedLive || PerformNullSession || PerformNullTrusts || PerformEnumInboundTrust)
            {
                if (String.IsNullOrEmpty(tasks.Server))
                {
                    tasks.Server = GetCurrentDomain();
                    if (String.IsNullOrEmpty(tasks.Server))
                    {
                        WriteInRed("This computer is not connected to a domain. The program couldn't guess the domain or server to connect.");
                        WriteInRed("Please run again this program with the flag --server <my.domain.com> or --server <mydomaincontroller.my.domain.com>");
                        DisplayHelp();
                        return false;
                    }
                }
                if (user != null)
                {
                    if (password == null)
                        password = AskCredential();
                    if (String.IsNullOrEmpty(userdomain))
                    {
                        tasks.Credential = new NetworkCredential(user, password);
                    }
                    else
                    {
                        tasks.Credential = new NetworkCredential(user, password, userdomain);
                    }
                }
            }
            if (PerformHealthCheckConsolidation)
            {
                if (String.IsNullOrEmpty(tasks.FileOrDirectory))
                {
                    tasks.FileOrDirectory = Directory.GetCurrentDirectory();
                }
                else
                {
                    if (!Directory.Exists(tasks.FileOrDirectory))
                    {
                        WriteInRed("The path specified by --xmls isn't a directory");
                        DisplayHelp();
                        return false;
                    }
                }
            }
            return true;
        }

        private void EnableLogFile()
        {
            Trace.AutoFlush = true;
            TextWriterTraceListener listener = new TextWriterTraceListener("trace.log");
            Trace.Listeners.Add(listener);
        }

        private void EnableLogConsole()
        {
            Trace.AutoFlush = true;
            ConsoleTraceListener listener = new ConsoleTraceListener();
            Trace.Listeners.Add(listener);
        }

        private string AskCredential()
        {
            StringBuilder builder = new StringBuilder();
            Console.WriteLine("Enter password: ");
            ConsoleKeyInfo nextKey = Console.ReadKey(true);

            while (nextKey.Key != ConsoleKey.Enter)
            {
                if (nextKey.Key == ConsoleKey.Backspace)
                {
                    if (builder.Length > 0)
                    {
                        builder.Remove(builder.Length -1, 1);
                        // erase the last * as well
                        Console.Write(nextKey.KeyChar);
                        Console.Write(" ");
                        Console.Write(nextKey.KeyChar);
                    }
                }
                else
                {
                    builder.Append(nextKey.KeyChar);
                    Console.Write("*");
                }
                nextKey = Console.ReadKey(true);
            }
            Console.WriteLine();
            return builder.ToString();
        }

        // interactive interface
        private void RunInteractiveMode()
        {
            tasks.InteractiveMode = true;
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("Using interactive mode.");
            Console.WriteLine("Do not forget that there are other command line switches like --help that you can use");
            Console.ResetColor();
            string whattodo = null;
			List<KeyValuePair<string, string>> choices = new List<KeyValuePair<string, string>>() { 
				new KeyValuePair<string, string>("healthcheck","Score the risk of a domain"), 
				new KeyValuePair<string, string>("graph","Analyze admin groups and delegations"),
				new KeyValuePair<string, string>("conso","Aggregate multiple reports into a single one"), 
				new KeyValuePair<string, string>("nullsession","Perform a specific security check"), 
				new KeyValuePair<string, string>("carto","Build a map of all interconnected domains"), 
				new KeyValuePair<string, string>("scanner","Perform specific security checks on workstations"), 
			};
            Console.WriteLine("What you would like to do?");
            whattodo = choices[SelectMenu(choices, 0)].Key;
            switch (whattodo)
            {
                case "":
                case "healthcheck":
                    PerformHealthCheckReport = true;
                    break;
                case "graph":
					PerformAdvancedLive = true;
                    break;
                case "carto":
                    PerformCarto = true;
                    break;
                case "conso":
                    PerformHealthCheckConsolidation = true;
                    break;
                case "nullsession":
                    PerformNullSession = true;
                    break;
                case "scanner":
                    PerformScanner = true;
                    break;
            }
			if (PerformScanner)
			{
				Console.ForegroundColor = ConsoleColor.Red;
				Console.WriteLine("WARNING");
				Console.WriteLine("Checking a lot of workstation in a short time using tcp/445 can raise alerts to a SOC. Be sure to have warned your security team.");
				Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("Select a scanner");
                Console.WriteLine("=============================");
                Console.ResetColor();
                whattodo = null;
				var scanners = ScannerBase.GetAllScanners();
				Console.WriteLine("What scanner whould you like to run ?");
					
				choices = new List<KeyValuePair<string, string>>();
				foreach(var scanner in scanners)
				{
					Type scannerType = scanner.Value;
					IScanner iscanner = (IScanner)Activator.CreateInstance(scannerType);
					string description = iscanner.Description;
					choices.Add(new KeyValuePair<string,string>(scanner.Key, description));
				}

				tasks.Scanner = scanners[choices[SelectMenu(choices)].Key];
			}
			if (PerformHealthCheckReport || PerformNullSession || PerformScanner || PerformAdvancedLive || PerformEnumInboundTrust)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("Select a domain or server");
                Console.WriteLine("=============================");
                Console.ResetColor();
                string defaultDomain = tasks.Server;
                if (String.IsNullOrEmpty(defaultDomain))
                    defaultDomain = GetCurrentDomain();
                while (true)
                {
                    if (!String.IsNullOrEmpty(defaultDomain))
                    {
                        Console.WriteLine("Please specify the domain or server to investigate (default:" + defaultDomain + ")");
                    }
                    else
                    {
                        Console.WriteLine("Please specify the domain or server to investigate:");
                    }
                    tasks.Server = Console.ReadLine();
                    if (String.IsNullOrEmpty(tasks.Server))
                    {
                        tasks.Server = defaultDomain;
                    }
                    if (!String.IsNullOrEmpty(tasks.Server))
                    {
                        break;
                    }
                }
            }
            if (PerformAdvancedLive)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("Indicate additional users");
                Console.WriteLine("=============================");
                Console.ResetColor();
                Console.WriteLine("Please specify any additional users to investigate (sAMAccountName, display name) and end by an empty line");
				tasks.NodesToInvestigate = new List<String>();
                whattodo = Console.ReadLine();
				while(!String.IsNullOrEmpty(whattodo))
                {
                    tasks.NodesToInvestigate.Add(whattodo);
					whattodo = Console.ReadLine();
                }
                
            }
        }

		static void printSelectMenu(List<KeyValuePair<string, string>> items, int defaultIndex, int top, int left)
		{
			bool hasDescription = false;
			int largerChoice = 0;
			for (int i = 0; i < items.Count; i++)
			{
				if (!String.IsNullOrEmpty(items[i].Value))
					hasDescription = true;
				int l = items[i].Key.Length;
				if (l > largerChoice)
					largerChoice = l;
			}
			Console.SetCursorPosition(left, top);
			for (int i = 0; i < items.Count; i++)
			{
				if (i == defaultIndex)
				{
					Console.BackgroundColor = ConsoleColor.Gray;
					Console.ForegroundColor = ConsoleColor.Black;
				}
				Console.Write("  " + (i + 1) + "-" + items[i].Key);
				if (hasDescription)
				{
					int diff = largerChoice - items[i].Key.Length;
					if (diff > 0)
						Console.Write(new String(' ', diff));
					if (!String.IsNullOrEmpty(items[i].Value))
						Console.Write("-" + items[i].Value);
				}
				Console.WriteLine();
				Console.ResetColor();
			}
		}

		public static int SelectMenu(List<KeyValuePair<string, string>> items, int defaultIndex = 0)
		{
			int top = Console.CursorTop;
			int left = Console.CursorLeft;
			int index = defaultIndex;
			Console.CursorVisible = false;
			while (true)
			{
				printSelectMenu(items, index, top, left);
				ConsoleKeyInfo ckey = Console.ReadKey(true);

				if (ckey.Key == ConsoleKey.DownArrow)
				{
					if (index == items.Count - 1)
					{
						//index = 0; //Remove the comment to return to the topmost item in the list
					}
					else { index++; }
				}
				else if (ckey.Key == ConsoleKey.UpArrow)
				{
					if (index <= 0)
					{
						//index = menuItem.Count - 1; //Remove the comment to return to the item in the bottom of the list
					}
					else { index--; }
				}
				else if (ckey.Key == ConsoleKey.Enter)
				{
					Console.CursorVisible = true;
					Console.ResetColor();
					return index;
				}
				else
				{
					int number;
					if (Int32.TryParse(ckey.KeyChar.ToString(), out number) && number > 0 && number <= 9 && (number <= items.Count))
					{
						Console.CursorVisible = true;
						Console.ResetColor();
						return number-1;
					}
				}
			}
		}

        private static void DisplayHelp()
        {
            Console.WriteLine("switch:");
            Console.WriteLine("  --help              : display this message");
            Console.WriteLine("  --interactive       : force the interactive mode");
            Console.WriteLine("  --log               : generate a log file");
            Console.WriteLine("  --log-console       : add log to the console");
            Console.WriteLine("");
            Console.WriteLine("Common options when connecting to the AD");
            Console.WriteLine("  --server <server>   : use this server (default: current domain controller)");
            Console.WriteLine("                        the special value * or *.forest do the healthcheck for all domains");
            Console.WriteLine("  --adws-port <port>  : use the port for ADWS (default: 9389)");
            Console.WriteLine("  --user <user>       : use this user (default: integrated authentication)");
            Console.WriteLine("  --password <pass>   : use this password (default: asked on a secure prompt)");
            Console.WriteLine("  --protocol <proto>  : selection the protocol to use among LDAP or ADWS (fastest)");
            Console.WriteLine("                      : ADWSThenLDAP (default), ADWSOnly, LDAPOnly, LDAPThenADWS");
            Console.WriteLine("");
            Console.WriteLine("  --carto             : perform a quick cartography with domains surrounding");
            Console.WriteLine(""); 
            Console.WriteLine("  --healthcheck       : perform the healthcheck (step1)");
            Console.WriteLine("    --api-endpoint <> : upload report via api call eg: http://server");
            Console.WriteLine("    --api-key  <key>  : and using the api key as registered");
            Console.WriteLine("    --explore-trust   : on domains of a forest, after the healthcheck, do the hc on all trusted domains except domains of the forest and forest trusts");
            Console.WriteLine("    --explore-forest-trust : on root domain of a forest, after the healthcheck, do the hc on all forest trusts discovered");
            Console.WriteLine("    --explore-trust and --explore-forest-trust can be run together");
            Console.WriteLine("    --explore-exception <domains> : comma separated values of domains that will not be explored automatically");
            Console.WriteLine("");
            Console.WriteLine("    --encrypt         : use an RSA key stored in the .config file to crypt the content of the xml report");
            Console.WriteLine("    --level <level>   : specify the amount of data found in the xml file");
            Console.WriteLine("                      : level: Full, Normal, Light");
            Console.WriteLine("    --no-enum-limit   : remove the max 100 users limitation in html report");
            Console.WriteLine("    --reachable       : add reachable domains to the list of discovered domains");
            Console.WriteLine("    --split-OU <level>: this is used to bypass the 30 minutes limit per ADWS request. Try 5 and increase 1 by 1.");
            Console.WriteLine("    --sendXmlTo <emails>: send xml reports to a mailbox (comma separated email)");
            Console.WriteLine("    --sendHtmlTo <emails>: send html reports to a mailbox");
            Console.WriteLine("    --sendAllTo <emails>: send html reports to a mailbox");
            Console.WriteLine("    --notifyMail <emails>: add email notification when the mail is received");
            Console.WriteLine("    --smtplogin <user>: allow smtp credentials ...");
            Console.WriteLine("    --smtppass <pass> : ... to be entered on the command line");
            Console.WriteLine("    --smtptls         : enable TLS/SSL in SMTP if used on other port than 465 and 587");
            Console.WriteLine("    --skip-null-session: do not test for null session");
            Console.WriteLine("    --webdirectory <dir>: upload the xml report to a webdav server");
            Console.WriteLine("    --webuser <user>  : optional user and password");
            Console.WriteLine("    --webpassword <password>");
            Console.WriteLine("");
            Console.WriteLine("  --generate-key      : generate and display a new RSA key for encryption");
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
            Console.WriteLine("  --graph             : perform the light compromise graph computation directly to the AD");
			Console.WriteLine("    --encrypt         : use an RSA key stored in the .config file to crypt the content of the xml report");
            Console.WriteLine("    --max-depth       : maximum number of relation to explore (default:30)");
            Console.WriteLine("    --max-nodes       : maximum number of node to include (default:1000)");
            Console.WriteLine("    --node <node>     : create a report based on a object");
            Console.WriteLine("                      : example: \"cn=name\" or \"name\"");
            Console.WriteLine("    --nodes <file>    : create x report based on the nodes listed on a file");
            Console.WriteLine("");
            Console.WriteLine("  --nullsession       : test for null session");
            Console.WriteLine("    --nslimit <number>: Limit the number of users to enumerate (default: 5)");
            Console.WriteLine("");
			Console.WriteLine("  --scanner <type>    : perform a scan on all computers of the domain (using --server)");
			var scanner = ScannerBase.GetAllScanners();
			var scannerNames = new List<string>(scanner.Keys);
			scannerNames.Sort();
			foreach (var scannerName in scannerNames)
			{
				Type scannerType = scanner[scannerName];
				IScanner iscanner = (IScanner)Activator.CreateInstance(scannerType);
				Console.ForegroundColor = ConsoleColor.Yellow;
				Console.WriteLine(iscanner.Name);
				Console.ResetColor();
				Console.WriteLine(iscanner.Description);
			}
			Console.WriteLine("");
			Console.WriteLine("  --nulltrusts        : check if the trusts can be enumerated using null session");
			Console.WriteLine("");
			Console.WriteLine("  --enuminbound <sid> : Enumerate accounts from inbound trust using its FQDN or sids");
			Console.WriteLine("                        Example of SID: S-1-5-21-4005144719-3948538632-2546531719");
			Console.WriteLine("");
            Console.WriteLine("  --upload-all-reports: use the API to upload all reports in the current directory");
            Console.WriteLine("    --api-endpoint <> : upload report via api call eg: http://server");
            Console.WriteLine("    --api-key  <key>  : and using the api key as registered");
            Console.WriteLine("                        Note: do not forget to set --level Full to send all the information available");
            Console.WriteLine("");

        }
    }


}


