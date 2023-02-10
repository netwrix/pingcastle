using PingCastle.ADWS;
using PingCastle.Exports;
using PingCastle.Report;
using PingCastle.Scanners;
using PingCastle.Cloud.Common;
using PingCastle.Cloud.Credentials;
using PingCastle.Cloud.RESTServices.Azure;
using PingCastle.Cloud.Tokens;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading.Tasks;
using System.Security;

namespace PingCastle
{
    public enum DisplayState
    {
        Exit,
        MainMenu,
        ScannerMenu,
        Run,
        AvancedMenu,
        AskForScannerParameter,
        ProtocolMenu,
        ExportMenu,
    }

    public class RuntimeSettings
    {
        public bool InteractiveMode { get; set; }

        public string Server { get; set; }
        public int Port { get; set; }
        public NetworkCredential Credential { get; set; }

        // must exists
        public string InputFile { get; set; }
        // must exists
        public string InputDirectory { get; set; }

        public Type Scanner { get; set; }
        public Type Export { get; set; }
        public IAzureCredential AzureCredential { get; set; }

        public string User { get; set; }
        public string Userdomain { get; set; }
        public SecureString Password { get; set; }

        public string InitForExportAsGuest { get; set; }

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
        public string mailNotification;
        public string smtpLogin;
        public string smtpPassword;
        public DateTime FilterReportDate = DateTime.MaxValue;
        public bool smtpTls;

        public string apiEndpoint;
        public string apiKey;
        public bool AnalyzeReachableDomains;
        public string botPipe;

        internal string privateKey = null;
        internal string tenantid = null;
        internal string clientid = null;
        internal string thumbprint = null;
        internal string p12file = null;
        internal string p12pass = null;
        internal bool p12passSet = false;
        internal bool usePrt = false;

        private bool CheckCertificate()
        {
            if (!string.IsNullOrEmpty(thumbprint) || !string.IsNullOrEmpty(privateKey))
            {
                if (string.IsNullOrEmpty(thumbprint))
                {
                    WriteInRed("--thumbprint must be completed when --private-key is set");
                    return false;
                }
                if (string.IsNullOrEmpty(privateKey))
                {
                    WriteInRed("--private-key must be completed when --thumbprint is set");
                    return false;
                }
                if (string.IsNullOrEmpty(clientid))
                {
                    WriteInRed("--clientid must be set when certificate authentication is configured");
                    return false;
                }
                if (string.IsNullOrEmpty(tenantid))
                {
                    WriteInRed("--tenantid must be set when certificate authentication is configured");
                    return false;
                }
                if (!string.IsNullOrEmpty(p12file))
                {
                    WriteInRed("--p12-file cannot be combined with --private-key");
                    return false;
                }
            }
            return true;
        }

        public bool CheckArgs()
        {
            return true;
            //return CheckCertificate();
        }

        #region display menu
        public DisplayState EnsureDataCompleted(params string[] requirements)
        {
            if (requirements.Contains("Scanner"))
            {
                if (Scanner == null)
                {
                    var state = DisplayScannerMenu();
                    if (state != DisplayState.Run)
                        return state;
                }
            }
            if (requirements.Contains("Export"))
            {
                if (Export == null)
                {
                    var state = DisplayExportMenu();
                    if (state != DisplayState.Run)
                        return state;
                }
            }
            if (requirements.Contains("Server"))
            {
                if (InteractiveMode)
                {
                    var state = DisplayAskServer();
                    if (state != DisplayState.Run)
                        return state;
                }
                if (string.IsNullOrEmpty(Server))
                {
                    Server = IPGlobalProperties.GetIPGlobalProperties().DomainName;
                }
                if (string.IsNullOrEmpty(Server))
                {
                    WriteInRed("This computer is not connected to a domain. The program couldn't guess the domain or server to connect.");
                    WriteInRed("Please run again this program with the flag --server <my.domain.com> or --server <mydomaincontroller.my.domain.com>");
                    return DisplayState.Exit;
                }
                if (!string.IsNullOrEmpty(User))
                {
                    if (Password == null)
                    {
                        if (!AskCredential())
                            return DisplayState.Exit;
                    }
                    if (!string.IsNullOrEmpty(Userdomain))
                    {
                        Credential = new NetworkCredential(User, Password, Userdomain);
                    }
                    else
                    {
                        Credential = new NetworkCredential(User, Password);
                    }
                }
            }
            if (requirements.Contains("AzureADCredential") || requirements.Contains("AzureADTenant"))
            {
                if (AzureCredential == null)
                {
                    if (!string.IsNullOrEmpty(privateKey))
                    {
                        var key = File.ReadAllText(privateKey);
                        AzureCredential = CertificateCredential.LoadFromKeyFile(clientid, tenantid, key, thumbprint);
                    }
                    if (!string.IsNullOrEmpty(p12file))
                    {
                        AzureCredential = CertificateCredential.LoadFromP12(clientid, tenantid, p12file, p12pass);
                    }
                    if (usePrt)
                    {
                        AzureCredential = new PRTCredential(tenantid);
                    }
                }
                if (AzureCredential == null)
                {
                    var state = DisplayAskAzureADCredential();
                    if (state != DisplayState.Run)
                        return state;
                }
            }
            if (requirements.Contains("AzureADTenant"))
            {
                var state = DisplayAskAzureADTenant();
                if (state != DisplayState.Run)
                    return state;
            }
            if (requirements.Contains("File"))
            {
                var state = DisplayAskForFile();
                if (state != DisplayState.Run)
                    return state;
            }
            if (requirements.Contains("Directory"))
            {
                if (string.IsNullOrEmpty(InputDirectory))
                {
                    InputDirectory = Directory.GetCurrentDirectory();
                }
                if (!Directory.Exists(InputDirectory))
                {
                    WriteInRed("No input directory has been provided");
                    return DisplayState.Exit;
                }
            }
            if (requirements.Contains("AzureADSeed"))
            {
                var state = DisplayAskForSeed();
                if (state != DisplayState.Run)
                    return state;
            }

            return DisplayState.Run;
        }

        public DisplayState DisplayScannerMenu()
        {
            var scanners = PingCastleFactory.GetAllScanners();

            var choices = new List<ConsoleMenuItem>();
            foreach (var scanner in scanners)
            {
                Type scannerType = scanner.Value;
                IScanner iscanner = PingCastleFactory.LoadScanner(scannerType);
                string description = iscanner.Description;
                choices.Add(new ConsoleMenuItem(scanner.Key, description));
            }
            choices.Sort((ConsoleMenuItem a, ConsoleMenuItem b)
                =>
            {
                return String.Compare(a.Choice, b.Choice);
            }
            );
            ConsoleMenu.Notice = "WARNING: Checking a lot of workstations may raise security alerts.";
            ConsoleMenu.Title = "Select a scanner";
            ConsoleMenu.Information = "What scanner whould you like to run ?";
            int choice = ConsoleMenu.SelectMenuCompact(choices, 1);
            if (choice == 0)
            {
                return DisplayState.Exit;
            }
            Scanner = scanners[choices[choice - 1].Choice];
            return DisplayState.Run;
        }

        public DisplayState DisplayExportMenu()
        {
            var exports = PingCastleFactory.GetAllExport();

            var choices = new List<ConsoleMenuItem>();
            foreach (var export in exports)
            {
                Type exportType = export.Value;
                IExport iexport = PingCastleFactory.LoadExport(exportType);
                string description = iexport.Description;
                choices.Add(new ConsoleMenuItem(export.Key, description));
            }
            choices.Sort((ConsoleMenuItem a, ConsoleMenuItem b)
                =>
            {
                return String.Compare(a.Choice, b.Choice);
            }
            );
            ConsoleMenu.Title = "Select an export";
            ConsoleMenu.Information = "What export whould you like to run ?";
            int choice = ConsoleMenu.SelectMenu(choices, 1);
            if (choice == 0)
            {
                return DisplayState.Exit;
            }
            Export = exports[choices[choice - 1].Choice];
            return DisplayState.Run;
        }

        DisplayState DisplayAskServer()
        {
            var defaultServer = IPGlobalProperties.GetIPGlobalProperties().DomainName;
            while (true)
            {
                if (!String.IsNullOrEmpty(defaultServer) || string.Equals(defaultServer, "(None)", StringComparison.OrdinalIgnoreCase))
                {
                    ConsoleMenu.Information = "Please specify the domain or server to investigate (default:" + defaultServer + ")";
                }
                else
                {
                    ConsoleMenu.Information = "Please specify the domain or server to investigate:";
                }
                ConsoleMenu.Title = "Select a domain or server";
                Server = ConsoleMenu.AskForString();
                if (!String.IsNullOrEmpty(Server))
                {
                    break;
                }
                if (!string.IsNullOrEmpty(defaultServer))
                {
                    Server = defaultServer;
                    break;
                }
            }
            return DisplayState.Run;
        }


        private DisplayState DisplayAskAzureADCredential()
        {
            List<ConsoleMenuItem> choices = new List<ConsoleMenuItem>() {
                new ConsoleMenuItem("askcredential","Ask credentials", "The identity may be asked multiple times during the healthcheck."),
            };

            var tokens = TokenFactory.GetRegisteredPRTIdentities();
            if (tokens.Count > 0)
            {
                choices.Insert(0, new ConsoleMenuItem("useprt", "Use SSO with the PRT stored on this computer", "Use the Primary Refresh Token available on this computer to connect automatically without credential prompting."));
            }

            ConsoleMenu.Title = "Which identity do you want to use?";
            ConsoleMenu.Information = "The program will use the choosen identity to perform the operation on the Azure Tenant.";
            int choice = ConsoleMenu.SelectMenu(choices);
            if (choice == 0)
                return DisplayState.Exit;

            AzureCredential = null;

            string whattodo = choices[choice - 1].Choice;
            switch (whattodo)
            {
                default:
                    break;
                case "askcredential":
                    AzureCredential = new UserCredential();
                    break;
                case "useprt":
                    AzureCredential = new PRTCredential();
                    break;

            }

            return DisplayState.Run;
        }

        private DisplayState DisplayAskAzureADTenant()
        {
            HttpClientHelper.LogComment = "DisplayAskTenant";
            ManagementApi.TenantListResponse p;
            try
            {
                var graph = new ManagementApi(AzureCredential);
                p = graph.ListTenants();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return DisplayState.Exit;
            }
            HttpClientHelper.LogComment = null;


            List<ConsoleMenuItem> choices = new List<ConsoleMenuItem>();
            foreach (var t in p.responses)
            {
                foreach (var t2 in t.content.value)
                {
                    choices.Add(new ConsoleMenuItem(t2.tenantId, t2.displayName + " (" + t2.countryCode + ")"));
                }
            }

            ConsoleMenu.Title = "Which tenant do you want to use?";
            ConsoleMenu.Information = "The program will use the choosen tenant to perform the operation on the Azure Tenant.";
            int choice = ConsoleMenu.SelectMenu(choices);
            if (choice == 0)
                return DisplayState.Exit;

            string whattodo = choices[choice - 1].Choice;
            AzureCredential.TenantidToQuery = whattodo;

            return DisplayState.Run;
        }

        DisplayState DisplayAskForFile()
        {
            while (String.IsNullOrEmpty(InputFile) || !File.Exists(InputFile))
            {
                ConsoleMenu.Title = "Select an existing file";
                ConsoleMenu.Information = "Please specify the file to open.";
                InputFile = ConsoleMenu.AskForString();
                ConsoleMenu.Notice = "The file " + InputFile + " was not found";
            }
            return DisplayState.Run;
        }

        DisplayState DisplayAskForDirectory()
        {
            while (String.IsNullOrEmpty(InputDirectory) || !Directory.Exists(InputDirectory))
            {
                ConsoleMenu.Title = "Select an existing directory";
                ConsoleMenu.Information = "Please specify the directory to open.";
                InputFile = ConsoleMenu.AskForString();
                ConsoleMenu.Notice = "The directory " + InputFile + " was not found";
            }
            return DisplayState.Run;
        }

        DisplayState DisplayAskForSeed()
        {
            while (String.IsNullOrEmpty(InitForExportAsGuest))
            {
                ConsoleMenu.Title = "Select the seed";
                ConsoleMenu.Information = @"To start the export, the program need to have a first user. It can be its objectId or its UPN (firstname.lastname@domain.com). The program accept many values if there are separted by a comma.";
                InitForExportAsGuest = ConsoleMenu.AskForString();

                // error message in case the query is not complete
                ConsoleMenu.Notice = "The seed cannot be empty";
            }
            return DisplayState.Run;
        }

        private bool AskCredential()
        {
            Password = new SecureString();
            Console.WriteLine("Enter password: ");
            ConsoleKeyInfo nextKey = Console.ReadKey(true);

            while (nextKey.Key != ConsoleKey.Enter)
            {
                if (nextKey.Key == ConsoleKey.Backspace)
                {
                    if (Password.Length > 0)
                    {
                        Password.RemoveAt(Password.Length - 1);
                        // erase the last * as well
                        Console.Write(nextKey.KeyChar);
                        Console.Write(" ");
                        Console.Write(nextKey.KeyChar);
                    }
                }
                else
                {
                    Password.AppendChar(nextKey.KeyChar);
                    Console.Write("*");
                }
                nextKey = Console.ReadKey(true);
            }
            Console.WriteLine();
            return true;
        }




        #endregion
        private void WriteInRed(string data)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(data);
            Trace.WriteLine("[Red]" + data);
            Console.ResetColor();
        }
    }
}
