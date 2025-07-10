using PingCastle.Exports;
using PingCastle.Scanners;
using PingCastle.Cloud.Common;
using PingCastle.Cloud.Credentials;
using PingCastle.Cloud.RESTServices.Azure;
using PingCastle.Cloud.Tokens;
using PingCastle.UserInterface;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
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
        PrivilegedModeMenu
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

        public bool IsPrivilegedMode { get; set; }

        public bool IsAgentLicense { get; set; }

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
        public List<string> AntivirusCustomServiceNames;
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

        private readonly IUserInterface _ui = UserInterfaceFactory.GetUserInterface();

        internal string privateKey = null;
        internal string tenantid = null;
        internal string clientid = null;
        internal string thumbprint = null;
        internal string p12file = null;
        internal string p12pass = null;
        internal bool p12passSet = false;
        internal bool usePrt = false;

        public void SetPrivateKey(string privateKey) => this.privateKey = privateKey;
        public void SetTenantId(string tenantId) => tenantid = tenantId;
        public void SetClientId(string clientId) => clientid = clientId;
        public void SetThumbprint(string thumbPrint) => thumbprint = thumbPrint;
        public void SetP12File(string p12File) => p12file = p12File;
        public void SetP12Pass(string p12Pass)
        {
            p12pass = p12Pass;
            p12passSet = true;
        }
        public void SetUsePrt(bool usePrt) => this.usePrt = usePrt;

        private bool CheckCertificate()
        {
            if (!string.IsNullOrEmpty(thumbprint) || !string.IsNullOrEmpty(privateKey))
            {
                if (string.IsNullOrEmpty(thumbprint))
                {
                    WriteError("--thumbprint must be completed when --private-key is set");
                    return false;
                }
                if (string.IsNullOrEmpty(privateKey))
                {
                    WriteError("--private-key must be completed when --thumbprint is set");
                    return false;
                }
                if (string.IsNullOrEmpty(clientid))
                {
                    WriteError("--clientid must be set when certificate authentication is configured");
                    return false;
                }
                if (string.IsNullOrEmpty(tenantid))
                {
                    WriteError("--tenantid must be set when certificate authentication is configured");
                    return false;
                }
                if (!string.IsNullOrEmpty(p12file))
                {
                    WriteError("--p12-file cannot be combined with --private-key");
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
                    WriteError("This computer is not connected to a domain. The program couldn't guess the domain or server to connect.");
                    WriteError("Please run again this program with the flag --server <my.domain.com> or --server <mydomaincontroller.my.domain.com>");
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
                    WriteError("No input directory has been provided");
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

            var choices = new List<MenuItem>();
            foreach (var scanner in scanners)
            {
                Type scannerType = scanner.Value;
                IScanner iscanner = PingCastleFactory.LoadScanner(scannerType);
                string description = iscanner.Description;
                choices.Add(new MenuItem(scanner.Key, description));
            }
            choices.Sort((MenuItem a, MenuItem b)
                =>
            {
                return String.Compare(a.Choice, b.Choice);
            }
            );
            _ui.Notice = "WARNING: Checking a lot of workstations may raise security alerts.";
            _ui.Title = "Select a scanner";
            _ui.Information = "What scanner would you like to run ?";
            _ui.IsCompactStyle = true;
            int choice = _ui.SelectMenu(choices, 1);
            if (choice == 0)
            {
                return DisplayState.Exit;
            }
            Scanner = scanners[choices[choice - 1].Choice];
            return DisplayState.Run;
        }

        public DisplayState DisplayPrivilegedModeMenu()
        {
            var choices = new List<MenuItem>
            {
                new MenuItem("Yes") {LongDescription = "Include checks that require high levels of Active Directory access"},
                new MenuItem("No") {LongDescription = "(Default) Do not include specific checks that require high levels of Active Directory access"}
            };

            _ui.Title = "Select the healthcheck mode";
            _ui.Information = "Do you want to use privileged mode?";
            _ui.IsAddExitItem = false;

            var choice = _ui.SelectMenu(choices, 2);
            IsPrivilegedMode = choice == 1;

            return DisplayState.Run;
        }

        public DisplayState DisplayAskAgentLicenseMenu()
        {
            var choices = new List<MenuItem>
            {
                new MenuItem("No") {LongDescription = "Default mode. License from config file"},
                new MenuItem("Yes") {LongDescription = "An agent license will be used"}
            };

            _ui.Title = "Please specify the license type";
            _ui.Information = "Do you want to use an agent license?";
            _ui.IsAddExitItem = false;

            var choice = _ui.SelectMenu(choices, 1);
            IsAgentLicense = choice == 2;

            return DisplayState.Run;
        }

        public DisplayState DisplayExportMenu()
        {
            var exports = PingCastleFactory.GetAllExport();

            var choices = new List<MenuItem>();
            foreach (var export in exports)
            {
                Type exportType = export.Value;
                IExport iexport = PingCastleFactory.LoadExport(exportType);
                string description = iexport.Description;
                choices.Add(new MenuItem(export.Key, description));
            }
            choices.Sort((MenuItem a, MenuItem b)
                =>
            {
                return String.Compare(a.Choice, b.Choice);
            }
            );

            _ui.Title = "Select an export";
            _ui.Information = "What export whould you like to run ?";
            int choice = _ui.SelectMenu(choices, 1);
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
                    _ui.Information = "Please specify the domain or server to investigate (default:" + defaultServer + ")";
                }
                else
                {
                    _ui.Information = "Please specify the domain or server to investigate:";
                }
                _ui.Title = "Select a domain or server";
                Server = _ui.AskForString();
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

        public DisplayState AskAgentLogin()
        {
            if(!string.IsNullOrEmpty(apiEndpoint) && !string.IsNullOrEmpty(apiKey))
                return DisplayState.Run;

            _ui.Title = "Please specify the agent login settings:";
            while(true)
            {
                if(string.IsNullOrEmpty(apiEndpoint))
                {
                    _ui.Information = "Enter the agent api endpoint:";
                    apiEndpoint = _ui.AskForString(false);
                    
                    if (!Uri.TryCreate(apiEndpoint, UriKind.Absolute, out var uri))
                    {
                        apiEndpoint = null;
                        _ui.Notice = "Unable to convert api-endpoint into an URI. Please try again.";
                        continue;
                    }

                    _ui.Notice = "";

                    if (!string.IsNullOrEmpty(apiKey))
                        break;
                }
                else if(string.IsNullOrEmpty(apiKey))
                {
                    _ui.Information = "Enter the agent api key:";
                    apiKey = _ui.AskForString(false);
                    if(string.IsNullOrEmpty(apiKey))
                        continue;

                    break;
                }
            }

            return DisplayState.Run;
        }
       

        private DisplayState DisplayAskAzureADCredential()
        {
            List<MenuItem> choices = new List<MenuItem>() {
                new MenuItem("askcredential","Ask credentials", "The identity may be asked multiple times during the healthcheck."),
            };

            var tokens = TokenFactory.GetRegisteredPRTIdentities();
            if (tokens.Count > 0)
            {
                choices.Insert(0, new MenuItem("useprt", "Use SSO with the PRT stored on this computer", "Use the Primary Refresh Token available on this computer to connect automatically without credential prompting."));
            }

            _ui.Title = "Which identity do you want to use?";
            _ui.Information = "The program will use the coosen identity to perform the operation on the Azure Tenant.";
            int choice = _ui.SelectMenu(choices);
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
                _ui.DisplayMessage(ex.Message);
                return DisplayState.Exit;
            }
            HttpClientHelper.LogComment = null;


            List<MenuItem> choices = new List<MenuItem>();
            foreach (var t in p.responses)
            {
                foreach (var t2 in t.content.value)
                {
                    choices.Add(new MenuItem(t2.tenantId, t2.displayName + " (" + t2.countryCode + ")"));
                }
            }

            _ui.Title = "Which tenant do you want to use?";
            _ui.Information = "The program will use the chosen tenant to perform the operation on the Azure Tenant.";
            int choice = _ui.SelectMenu(choices);
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
                _ui.Title = "Select an existing file";
                _ui.Information = "Please specify the file to open.";
                InputFile = _ui.AskForString();
                _ui.Notice = "The file " + InputFile + " was not found";
            }
            return DisplayState.Run;
        }

        DisplayState DisplayAskForDirectory()
        {
            while (String.IsNullOrEmpty(InputDirectory) || !Directory.Exists(InputDirectory))
            {
                _ui.Title = "Select an existing directory";
                _ui.Information = "Please specify the directory to open.";
                InputFile = _ui.AskForString();
                _ui.Notice = "The directory " + InputFile + " was not found";
            }
            return DisplayState.Run;
        }

        DisplayState DisplayAskForSeed()
        {
            while (String.IsNullOrEmpty(InitForExportAsGuest))
            {
                _ui.Title = "Select the seed";
                _ui.Information = @"To start the export, the program need to have a first user. It can be its objectId or its UPN (firstname.lastname@domain.com). The program accept many values if there are separted by a comma.";
                InitForExportAsGuest = _ui.AskForString();

                // error message in case the query is not complete
                _ui.Notice = "The seed cannot be empty";
            }
            return DisplayState.Run;
        }

        private bool AskCredential()
        {
            Password = _ui.ReadInputPassword("Enter the password");
            return true;
        }

        #endregion
        private void WriteError(string data)
        {
            _ui.DisplayError(data);
            Trace.WriteLine("[Red]" + data);
        }
    }
}
