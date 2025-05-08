//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.ADWS;
using PingCastle.Data;
using PingCastle.Graph.Reporting;
using PingCastle.misc;
using PingCastle.PingCastleLicense;
using PingCastle.RPC;
using PingCastle.Rules;
using PingCastle.Scanners;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Permissions;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Xml;

namespace PingCastle.Healthcheck
{
    public class HealthcheckAnalyzer : IPingCastleAnalyzer<HealthcheckData>
    {
        public static bool SkipNullSession { get; set; }
        public static bool SkipRPC { get; set; }
        HealthcheckData healthcheckData;

        private const string LatinUpperCase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        private const string LatinLowerCase = "abcdefghijklmnopqrstuvwxyz";

        private static readonly string[] CommonAccountProperties = new string[] {
                                                                    "distinguishedName",
                                                                    "name",
                                                                    "sAMAccountName",
                                                                    "whenCreated",
                                                                    "lastLogonTimestamp",
                                                                    "replPropertyMetaData",
                                                                    "pwdLastSet",
                                                                    };

        public bool LimitHoneyPot = true;

        public HealthcheckAnalyzer()
        {
            if (Environment.OSVersion.Version.Major < 6)
            {
                SkipNullSession = true;
            }
            else if (Environment.OSVersion.Version.Major == 6 && Environment.OSVersion.Version.Minor == 0)
            {
                SkipNullSession = true;
            }
        }

        private void DisplayAdvancement(string data)
        {
            string value = "[" + DateTime.Now.ToLongTimeString() + "] " + data;
            Console.WriteLine(value);
            Trace.WriteLine(value);
        }

        private void DisplayContactSupport()
        {
            var license = LicenseCache.Instance.GetLicense();
            var IsBasicEdition = license.IsBasic();

            if (IsBasicEdition)
                DisplayAdvancementWarning("Please visit https://github.com/netwrix/pingcastle/issues to log an issue with a trace file.");
            else
                DisplayAdvancementWarning("Please visit the Netwrix support portal, https://www.netwrix.com/support.html, to open a support case with the trace file generated.");
        }

        private void DisplayAdvancementWarning(string data)
        {
            string value = "[" + DateTime.Now.ToLongTimeString() + "] " + data;
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine(value);
            Console.ResetColor();
            Trace.WriteLine(value);
        }

        public HealthcheckData GenerateCartoReport(string server, int port, NetworkCredential credential, bool AnalyzeReachableDomains)
        {
            healthcheckData = new HealthcheckData();
            ADDomainInfo domainInfo = null;
            using (ADWebService adws = new ADWebService(server, port, credential))
            {
                domainInfo = adws.DomainInfo;
                GenerateGeneralData(domainInfo, adws);
                GenerateTrustData(domainInfo, adws);
                if (AnalyzeReachableDomains)
                {
                    GenerateReachableTrustData(domainInfo, adws);
                }
            }
            return healthcheckData;
        }

        public HealthcheckData PerformAnalyze(PingCastleAnalyzerParameters parameters)
        {
            healthcheckData = new HealthcheckData();
            LoadHoneyPotData();
            ADDomainInfo domainInfo = null;
            DisplayAdvancement("Getting domain information (" + parameters.Server + ")");
            if (RestrictedToken.IsUsingRestrictedToken)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("Warning: the program is running under a restricted token.");
                Console.WriteLine("That means that the software does not have the same rights than the current user to query the Active Directory. Some information will be missing such as creation date or DNS zones.");
                Console.WriteLine("To solve this problem, run the program elevated, aka as administrator");
                Console.ResetColor();
            }
            using (ADWebService adws = new ADWebService(parameters.Server, parameters.Port, parameters.Credential))
            {
                domainInfo = adws.DomainInfo;
                if (adws.useLdap)
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("Performance warning: using LDAP instead of ADWS");
                    Console.ResetColor();
                }
                DisplayAdvancement("Gathering general data");
                GenerateGeneralData(domainInfo, adws);
                CheckRootDomainProperties(domainInfo, adws);

                DisplayAdvancement("Gathering user data");
                GenerateUserData(domainInfo, adws);
                GenerateGroupSidHistoryData(domainInfo, adws);
                DisplayAdvancement("Gathering computer data");
                GenerateComputerData(domainInfo, adws);
                DisplayAdvancement("Gathering trust data");
                GenerateTrustData(domainInfo, adws);
                if (parameters.PerformExtendedTrustDiscovery)
                {
                    DisplayAdvancement("Gathering reachable domains data");
                    GenerateReachableTrustData(domainInfo, adws);
                }
                DisplayAdvancement("Gathering privileged group and permissions data");
                GeneratePrivilegedGroupAndPermissionsData(domainInfo, adws, parameters);
                DisplayAdvancement("Gathering delegation data");
                GenerateDelegationData(domainInfo, adws);
                DisplayAdvancement("Gathering gpo data");
                GenerateGPOData(domainInfo, adws);
                GeneratePSOData(domainInfo, adws);
                DisplayAdvancement("Gathering pki data");
                GeneratePKIData(domainInfo, adws);
                DisplayAdvancement("Gathering sccm data");
                GenerateSCCMData(domainInfo, adws);
                DisplayAdvancement("Gathering exchange data");
                GenerateExchangeInfo(domainInfo, adws);
                DisplayAdvancement("Gathering anomaly data");
                GenerateAnomalies(domainInfo, adws);
                DisplayAdvancement("Gathering dns data");
                GenerateDnsData(domainInfo, adws);
                DisplayAdvancement("Gathering WSUS data");
                GenerateWSUSData(domainInfo, adws);
                DisplayAdvancement("Gathering MSOL data");
                GenerateMSOLData(domainInfo, adws);
                DisplayAdvancement("Gathering domain controller data" + (SkipNullSession ? null : " (including null session)" + (SkipRPC ? null : " (including RPC tests)")));
                GenerateDomainControllerData(domainInfo, adws, parameters);
                GenerateRODCData(domainInfo, adws);
                GenerateRODCKrbtgtOrphans(domainInfo, adws);
                GenerateFSMOData(domainInfo, adws);
                GenerateCheckDCConfig(domainInfo, adws);
                GenerateCheckFRS(domainInfo, adws);
                DisplayAdvancement("Gathering network data");
                GenerateNetworkData(domainInfo, adws);
            }
            DisplayAdvancement("Computing risks");
            var rules = new RuleSet<HealthcheckData>();
            healthcheckData.RiskRules = new List<HealthcheckRiskRule>();
            rules.InfrastructureSettings = InfrastructureSettings.GetInfrastructureSettings();
            foreach (var rule in rules.ComputeRiskRules(healthcheckData))
            {
                HealthcheckRiskRule risk = new HealthcheckRiskRule();
                risk.Points = rule.Points;
                risk.Category = rule.Category;
                risk.Model = rule.Model;
                risk.RiskId = rule.RiskId;
                risk.Rationale = rule.Rationale;
                risk.Details = rule.Details;
                healthcheckData.RiskRules.Add(risk);
            }
            DisplayAdvancement("Export completed");
            healthcheckData.SetIntegrity();
            return healthcheckData;
        }

        private void LoadHoneyPotData()
        {
            var s = HoneyPotSettings.GetHoneyPotSettings();
            if (s == null)
                return;
            if (s.HoneyPots.Count > 25 && LimitHoneyPot)
            {
                throw new PingCastleException("You entered more than 25 HoneyPots in the configuration. Honey Pots should not be used as a way to setup exceptions to rules");
            }
            healthcheckData.ListHoneyPot = new List<HealthcheckAccountDetailData>();
            foreach (SingleHoneyPotSettings h in s.HoneyPots)
            {
                healthcheckData.ListHoneyPot.Add(new HealthcheckAccountDetailData() { Name = h.samAccountName, DistinguishedName = h.distinguishedName });
            }
        }

        public class ReachableDomainInfo : IComparable<ReachableDomainInfo>
        {
            public string domain { get; set; }

            public ReachableDomainInfo(string domain)
            {
                this.domain = domain;
            }
            public override bool Equals(object obj)
            {
                if (obj == null)
                    return false;
                ReachableDomainInfo d = obj as ReachableDomainInfo;
                if (d == null)
                    return false;
                return domain.Equals(d.domain, StringComparison.InvariantCultureIgnoreCase);
            }
            public override int GetHashCode()
            {
                return domain.GetHashCode();
            }

            public int CompareTo(ReachableDomainInfo other)
            {
                return domain.CompareTo(other.domain);
            }
        }

        public List<ReachableDomainInfo> GetAllReachableDomains(int port, NetworkCredential credential)
        {
            List<ReachableDomainInfo> domains = new List<ReachableDomainInfo>();
            string root = IPGlobalProperties.GetIPGlobalProperties().DomainName.ToLowerInvariant();
            if (String.IsNullOrEmpty(root))
                return domains;
            ExploreReachableDomain(root, "current domain", port, credential, domains);
            // sort the domain by name
            domains.Sort();
            return domains;
        }

        private void ExploreReachableDomain(string domainToExplore, string sourceForDisplay, int port, NetworkCredential credential,
                                                            List<ReachableDomainInfo> domainlist)
        {
            string forestToExplore = null;
            // classic graph exploration algorithm
            string[] properties = new string[] {
                        "trustPartner",
                        "trustAttributes",
                        "trustDirection",
                        "trustType",
                        "msDS-TrustForestTrustInfo",
            };
            ADWebService adws = null;
            try
            {
                DisplayAdvancement("Exploring " + domainToExplore + " (source:" + sourceForDisplay + ")");
                adws = new ADWebService(domainToExplore, port, credential);
                ADDomainInfo domainInfo = adws.DomainInfo;
                // if we are here that means that ADWS works
                ReachableDomainInfo rdi = new ReachableDomainInfo(domainToExplore);
                if (!domainlist.Contains(rdi))
                {
                    Trace.WriteLine("Adding " + domainToExplore + " as user input");
                    domainlist.Add(rdi);
                }
                if (domainInfo.ForestName != domainInfo.DomainName)
                {
                    forestToExplore = domainInfo.ForestName;
                    Trace.WriteLine("Changing forest to explore: " + forestToExplore);
                }
                WorkOnReturnedObjectByADWS callback =
                (ADItem x) =>
                {
                    Trace.WriteLine("* Examining trust " + x.TrustPartner);
                    // inbound trust
                    if (x.TrustDirection == 2)
                    {
                        Trace.WriteLine("Ignoring inbound trust");
                        return;
                    }
                    rdi = new ReachableDomainInfo(x.TrustPartner);
                    if (!domainlist.Contains(rdi))
                    {
                        Trace.WriteLine("Adding " + x.TrustPartner + " as direct target");
                        domainlist.Add(rdi);
                    }
                    if (x.msDSTrustForestTrustInfo != null)
                    {
                        foreach (HealthCheckTrustDomainInfoData di in x.msDSTrustForestTrustInfo)
                        {
                            Trace.WriteLine("msDSTrustForestTrustInfo constains " + di.DnsName);
                            rdi = new ReachableDomainInfo(di.DnsName);
                            if (!domainlist.Contains(rdi))
                            {
                                Trace.WriteLine("Adding " + di.DnsName + " as msDSTrustForestTrustInfo target");
                                domainlist.Add(rdi);
                            }
                        }
                    }
                };
                adws.Enumerate(domainInfo.DefaultNamingContext, "(ObjectCategory=trustedDomain)", properties, callback);
                Trace.WriteLine("Done");
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Unable to explore " + domainToExplore + " (" + ex.Message + ")");
                Console.ResetColor();
                Trace.WriteLine("Unable to explore " + domainToExplore + " (" + ex.Message + ")");
                Trace.WriteLine(ex.StackTrace);
            }
            finally
            {
                if (adws != null)
                    adws.Dispose();
            }
            if (!String.IsNullOrEmpty(forestToExplore))
            {
                ExploreReachableDomain(forestToExplore, domainToExplore, port, credential, domainlist);
            }
        }


        private void GenerateGeneralData(ADDomainInfo domainInfo, ADWebService adws)
        {
            // adding the domain sid
            string[] properties = new string[] { "objectSid", "whenCreated" };
            adws.Enumerate(domainInfo.DefaultNamingContext,
                                            "(&(objectClass=domain)(distinguishedName=" + domainInfo.DefaultNamingContext + "))",
                                            properties, (ADItem aditem) => { domainInfo.DomainSid = aditem.ObjectSid; domainInfo.CreationDate = aditem.WhenCreated; }, "Base");

            healthcheckData.DomainFQDN = domainInfo.DomainName;
            healthcheckData.ForestFQDN = domainInfo.ForestName;
            if (domainInfo.DomainSid != null)
                healthcheckData.DomainSid = domainInfo.DomainSid.Value;
            healthcheckData.DomainCreation = domainInfo.CreationDate;

            // adding the domain Netbios name
            string[] propertiesNetbios = new string[] { "nETBIOSName" };
            adws.Enumerate("CN=Partitions," + domainInfo.ConfigurationNamingContext,
                                            "(&(objectCategory=crossRef)(systemFlags:1.2.840.113556.1.4.803:=3)(nETBIOSName=*)(nCName=" + domainInfo.DefaultNamingContext + "))",
                                            propertiesNetbios,
                                            (ADItem aditem) =>
                                            {
                                                domainInfo.NetBIOSName = aditem.NetBIOSName;
                                            }
                                            , "OneLevel");
            // adding the schema version
            string[] propertiesSchema = new string[] { "objectVersion", "replPropertyMetaData", "schemaInfo" };
            adws.Enumerate(domainInfo.SchemaNamingContext,
                                            "(objectClass=dMD)",
                                            propertiesSchema, (ADItem aditem) =>
                                            {
                                                domainInfo.SchemaVersion = aditem.ObjectVersion;
                                                // version stored in big endian
                                                if (aditem.SchemaInfo != null)
                                                    domainInfo.SchemaInternalVersion = aditem.SchemaInfo[1] * 0x1000000 + aditem.SchemaInfo[2] * 0x10000 + aditem.SchemaInfo[3] * 0x100 + aditem.SchemaInfo[4];
                                                if (aditem.ReplPropertyMetaData != null && aditem.ReplPropertyMetaData.ContainsKey(0x9054E))
                                                {
                                                    domainInfo.SchemaLastChanged = aditem.ReplPropertyMetaData[0x9054E].LastOriginatingChange;
                                                }
                                            }, "Base");
            healthcheckData.NetBIOSName = domainInfo.NetBIOSName;
            healthcheckData.ForestFunctionalLevel = domainInfo.ForestFunctionality;
            healthcheckData.DomainFunctionalLevel = domainInfo.DomainFunctionality;
            healthcheckData.SchemaVersion = domainInfo.SchemaVersion;
            healthcheckData.SchemaInternalVersion = domainInfo.SchemaInternalVersion;
            healthcheckData.SchemaLastChanged = domainInfo.SchemaLastChanged;
            healthcheckData.GenerationDate = DateTime.Now;

            string[] propertiesEnabledFeature = new string[] { "msDS-EnabledFeature" };
            adws.Enumerate("CN=Partitions," + domainInfo.ConfigurationNamingContext,
                                        "(objectClass=*)",
                                        propertiesEnabledFeature, (ADItem aditem) =>
                                        {
                                            if (aditem.msDSEnabledFeature != null)
                                            {
                                                foreach (string feature in aditem.msDSEnabledFeature)
                                                {
                                                    if (feature.StartsWith("CN=Recycle Bin Feature,", StringComparison.InvariantCultureIgnoreCase))
                                                    {
                                                        healthcheckData.IsRecycleBinEnabled = true;
                                                    }
                                                }
                                            }
                                        }, "Base");

            if (healthcheckData.DomainFunctionalLevel >= 2)
            {
                string[] propertiesEstimate = new string[] { "msDS-Approx-Immed-Subordinates" };
                int count = 0;
                adws.Enumerate(domainInfo.DefaultNamingContext,
                                        "(|(objectClass=container)(objectClass=organizationalunit))",
                                        propertiesEstimate, (ADItem aditem) =>
                                            {
                                                count += aditem.msDSApproxImmedSubordinates;
                                            }
                );
                if (count > 0)
                {
                    DisplayAdvancement("This domain contains approximatively " + count + " objects");
                }
            }

            adws.Enumerate(domainInfo.DefaultNamingContext,
                                       "(objectSid=" + ADConnection.EncodeSidToString(domainInfo.DomainSid + "-" + 521) + ")",
                                        new string[] { "distinguishedName", "whenCreated" }, (ADItem aditem) =>
                                        {
                                            healthcheckData.DCWin2008Install = aditem.WhenCreated;
                                        });

            GetAzureInfo(domainInfo, adws);

            Version version = Assembly.GetExecutingAssembly().GetName().Version;
            healthcheckData.EngineVersion = version.ToString(4);
#if DEBUG
            healthcheckData.EngineVersion += " Beta";
#endif

            healthcheckData.WinTrustLevel = ConsoleMenu.CheckWinTrustFlags(typeof(Program).Assembly);
            healthcheckData.Level = PingCastleReportDataExportLevel.Full;

        }

        private void GetAzureInfo(ADDomainInfo domainInfo, ADWebService adws)
        {
            string[] propertiesAzureHybird = new string[] { "keywords" };
            adws.Enumerate("CN=Services," + domainInfo.ConfigurationNamingContext,
                                        "(name=62a0ff2e-97b9-4513-943f-0d221bd30080)",
                                        propertiesAzureHybird, (ADItem aditem) =>
                                        {
                                            if (aditem.Keywords != null)
                                            {
                                                foreach (string feature in aditem.Keywords)
                                                {
                                                    var i = feature.Split(':');
                                                    if (i.Length == 2)
                                                    {
                                                        if (i[0] == "azureADName")
                                                        {
                                                            healthcheckData.AzureADName = i[1];
                                                        }
                                                        else if (i[0] == "azureADId")
                                                        {
                                                            healthcheckData.AzureADId = i[1];
                                                        }
                                                    }
                                                }
                                            }
                                        });

            adws.Enumerate("CN=System," + domainInfo.DefaultNamingContext,
                                        "(name=900274c4-b7d2-43c8-90ee-00a9f650e335)",
                                        propertiesAzureHybird, (ADItem aditem) =>
                                        {
                                            if (aditem.Keywords != null && aditem.Keywords.Length > 0)
                                            {
                                                string json = aditem.Keywords[0];
                                                // unfortunately no json serializer in .net 2.0 (DataContractJsonSerializer or JavaScriptSerializer)
                                                const string mark1 = "\"ComputerAccountSid\":\"";
                                                int i = json.IndexOf(mark1);
                                                if (i > 0)
                                                {
                                                    int i2 = json.IndexOf('"', i + mark1.Length + 5);
                                                    if (i2 > 0)
                                                    {
                                                        string accountSid = json.Substring(i + mark1.Length, i2 - i - mark1.Length);
                                                        healthcheckData.AzureADKerberosSid = accountSid;
                                                    }
                                                }

                                            }
                                        });

            if (!string.IsNullOrEmpty(healthcheckData.AzureADId))
            {
                adws.Enumerate(domainInfo.DefaultNamingContext,
                                        "(objectClass=msDS-DeviceRegistrationService)",
                                        new string[] { "distinguishedName", "msDS-DeviceLocation" }, (ADItem aditem) =>
                                        {
                                            Trace.WriteLine("Azure Device Registration enabled");
                                        });
            }
        }

        public const string userFilter = "(|(&(objectClass=user)(objectCategory=person))(objectcategory=msDS-GroupManagedServiceAccount)(objectcategory=msDS-ManagedServiceAccount))";
        public static string[] userProperties = new string[] {
                        "distinguishedName",
                        "lastLogonTimestamp",
                        "msDS-SupportedEncryptionTypes",
                        "name",
                        "objectClass",
                        "objectSid",
                        "primaryGroupID",
                        "pwdLastSet",
                        "sAMAccountName",
                        "scriptPath",
                        "servicePrincipalName",
                        "sIDHistory",
                        "userAccountControl",
                        "whenCreated",
            };

        private void GenerateUserData(ADDomainInfo domainInfo, ADWebService adws)
        {
            var pwdDistribution = new Dictionary<int, int>();

            Dictionary<string, int> loginscript = new Dictionary<string, int>();


            WorkOnReturnedObjectByADWS callback =
                (ADItem x) =>
                {
                    try
                    {
                        if (x.ObjectSid != null)
                        {
                            // krbtgt
                            if (x.ObjectSid.IsWellKnown(System.Security.Principal.WellKnownSidType.AccountKrbtgtSid))
                            {
                                // krbtgt will be processed after - this avoid applying a filter on the object class
                                return;
                            }
                            // admin account
                            if (x.ObjectSid.IsWellKnown(System.Security.Principal.WellKnownSidType.AccountAdministratorSid))
                            {
                                healthcheckData.AdminLastLoginDate = x.LastLogonTimestamp;
                                healthcheckData.AdminAccountName = x.SAMAccountName;
                            }
                            if (x.ObjectSid.IsWellKnown(System.Security.Principal.WellKnownSidType.AccountGuestSid))
                            {
                                // added a check to make sur useraccountcontrol is not zero (happens on DC)
                                if (x.UserAccountControl != 0 && (x.UserAccountControl & 0x00000002) == 0)
                                {
                                    healthcheckData.GuestEnabled = true;
                                }
                            }
                        }
                        // ignore trust account
                        if (x.Name.EndsWith("$", StringComparison.InvariantCultureIgnoreCase) && ((x.UserAccountControl & 2048) != 0))
                        {
                            return;
                        }
                        if (!ProcessAccountData(healthcheckData.UserAccountData, x, false, healthcheckData.DCWin2008Install, healthcheckData.ListHoneyPot))
                            return;

                        // only enabled accounts and no guest account
                        if ((x.UserAccountControl & 0x00000002) == 0)
                        {
                            // login script
                            string scriptName = "None";
                            if (!String.IsNullOrEmpty(x.ScriptPath))
                            {
                                scriptName = x.ScriptPath.ToLowerInvariant();
                            }
                            if (!loginscript.ContainsKey(scriptName))
                                loginscript[scriptName] = 1;
                            else
                                loginscript[scriptName]++;
                            // avoid system objects where the whenCreated date in not set
                            // ex: guest, krbtgt for rodc, ...
                            if (x.WhenCreated != DateTime.MinValue)
                            {
                                var i = ConvertPwdLastSetToKey(x);
                                if (pwdDistribution.ContainsKey(i))
                                    pwdDistribution[i]++;
                                else
                                    pwdDistribution[i] = 1;
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Trace.WriteLine("Exception while working on " + x.DistinguishedName);
                        DisplayAdvancementWarning("Exception while working on " + x.DistinguishedName + "(" + ex.Message + ")");
                        DisplayContactSupport();
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine(ex.StackTrace);
                        Console.ResetColor();
                        Trace.WriteLine(ex.ToString());
                    }
                };

            adws.Enumerate(() =>
                {
                    healthcheckData.UserAccountData = new HealthcheckAccountData();
                    loginscript.Clear();
                },
                domainInfo.DefaultNamingContext, userFilter, userProperties, callback, "SubTree");

            healthcheckData.LoginScript = new List<HealthcheckLoginScriptData>();
            foreach (string key in loginscript.Keys)
            {
                var script = new HealthcheckLoginScriptData(key, loginscript[key]);
                script.Delegation = CheckScriptPermission(adws, domainInfo, script.LoginScript);
                healthcheckData.LoginScript.Add(script);
            }

            healthcheckData.PasswordDistribution = new List<HealthcheckPwdDistributionData>();

            foreach (var p in pwdDistribution)
            {
                healthcheckData.PasswordDistribution.Add(new HealthcheckPwdDistributionData() { HigherBound = p.Key, Value = p.Value });
            }
        }

        private int ConvertPwdLastSetToKey(ADItem x)
        {
            var dateTime = x.PwdLastSet;
            if (x.PwdLastSet == DateTime.MinValue)
                dateTime = x.WhenCreated;
            return ConvertDateToKey(dateTime);

        }

        public static int ConvertDateToKey(DateTime dateTime)
        {
            var t = (DateTime.Now - dateTime).Days;
            if (t < 0) t = 0;
            return t / 30;
        }

        List<HealthcheckScriptDelegationData> CheckScriptPermission(IADConnection adws, ADDomainInfo domainInfo, string file)
        {
            var output = new List<HealthcheckScriptDelegationData>();
            if (file == "None")
                return output;
            try
            {
                if (!file.StartsWith("\\\\"))
                {
                    file = adws.FileConnection.PathCombine(@"\\" + domainInfo.DnsHostName + @"\SYSVOL\" + domainInfo.DomainName + @"\scripts", file);
                }
                if (!adws.FileConnection.FileExists(file))
                {
                    return output;
                }
                var security = adws.FileConnection.GetFileSecurity(file);
                var accessRules = security.GetAccessRules(true, true, typeof(SecurityIdentifier));
                if (accessRules == null)
                    return output;

                foreach (FileSystemAccessRule rule in accessRules)
                {
                    if (rule.AccessControlType == AccessControlType.Deny)
                        continue;
                    if ((FileSystemRights.Write & rule.FileSystemRights) != FileSystemRights.Write)
                        continue;

                    var sid = (SecurityIdentifier)rule.IdentityReference;
                    var account = MatchesBadUsersToCheck(sid);
                    if (!account.HasValue)
                        continue;
                    output.Add(new HealthcheckScriptDelegationData() { Account = account.Value.Value, Right = rule.FileSystemRights.ToString() });
                }
            }
            catch (Exception ex)
            {
                Trace.WriteLine("Exception CheckScriptPermission " + ex.Message);
            }
            return output;
        }

        public static bool ProcessAccountData(IAddAccountData data, ADItem x, bool computerCheck, DateTime DCWin2008Install, List<HealthcheckAccountDetailData> ListHoneyPot = null)
        {
            // see https://msdn.microsoft.com/fr-fr/library/windows/desktop/ms680832%28v=vs.85%29.aspx for the flag
            if (ListHoneyPot != null && ListHoneyPot.Count > 0)
            {
                foreach (var h in ListHoneyPot)
                {
                    if (string.Equals(h.Name, x.SAMAccountName, StringComparison.InvariantCultureIgnoreCase))
                    {
                        // ignore the account
                        h.Name = x.SAMAccountName;
                        h.CreationDate = x.WhenCreated;
                        h.DistinguishedName = x.DistinguishedName;
                        h.LastLogonDate = x.LastLogonTimestamp;
                        return false;
                    }
                    if (string.Equals(h.DistinguishedName, x.DistinguishedName, StringComparison.InvariantCultureIgnoreCase))
                    {
                        // ignore the account
                        h.Name = x.SAMAccountName;
                        h.CreationDate = x.WhenCreated;
                        h.DistinguishedName = x.DistinguishedName;
                        h.LastLogonDate = x.LastLogonTimestamp;
                        return false;
                    }
                }
            }
            data.AddWithoutDetail(null);
            if (x.DistinguishedName.Contains("cnf:"))
            {
                data.AddDetail("Duplicate", GetAccountDetail(x));
            }
            else if (!String.IsNullOrEmpty(x.SAMAccountName) && x.SAMAccountName.StartsWith("$duplicate-", StringComparison.InvariantCultureIgnoreCase))
            {
                data.AddDetail("Duplicate", GetAccountDetail(x));
            }
            if ((x.UserAccountControl & 0x00000002) != 0)
                data.AddWithoutDetail("Disabled");
            else
            {
                data.AddWithoutDetail("Enabled");

                if (x.WhenCreated.AddMonths(6) > DateTime.Now || x.LastLogonTimestamp.AddMonths(6) > DateTime.Now || x.PwdLastSet.AddMonths(6) > DateTime.Now)
                {
                    data.AddWithoutDetail("Active");
                }
                else
                {
                    data.AddDetail("Inactive", GetAccountDetail(x));
                }
                if ((x.UserAccountControl & 0x400000) != 0)
                {
                    data.AddDetail("NoPreAuth", GetAccountDetail(x));
                }
                if ((x.UserAccountControl & 0x00000010) != 0)
                {
                    data.AddDetail("Locked", GetAccountDetail(x));
                }
                if ((x.UserAccountControl & 0x00010000) != 0)
                {
                    // see https://techcommunity.microsoft.com/t5/exchange-team-blog/exchange-2013-2016-monitoring-mailboxes/ba-p/611004?msclkid=bd3898eeb18f11ecb0ad418f45f9d755
                    // exception for exchange accounts whose password is changed regularly
                    if (x.SAMAccountName.StartsWith("HealthMailbox", StringComparison.OrdinalIgnoreCase) && x.PwdLastSet.AddDays(40) > DateTime.Now)
                    {

                    }
                    else
                    {
                        data.AddDetail("PwdNeverExpires", GetAccountDetail(x));
                    }
                }
                if ((x.UserAccountControl & 0x00000020) != 0)
                {
                    // avoid to alert about exchange mailboxes
                    if (!x.DistinguishedName.Contains(",CN=Monitoring Mailboxes,"))
                    {
                        data.AddDetail("PwdNotRequired", GetAccountDetail(x));
                    }
                }
                ProcessSIDHistory(x, data);
                // check for bad primary group
                if (!computerCheck)
                {
                    // not domain users & guest or the guest account
                    if (x.PrimaryGroupID != 513 && x.PrimaryGroupID != 514 && x.ObjectSid != null && !x.ObjectSid.IsWellKnown(System.Security.Principal.WellKnownSidType.AccountGuestSid)
                        && !(x.PrimaryGroupID == 515 && (string.Equals(x.Class, "msDS-GroupManagedServiceAccount", StringComparison.OrdinalIgnoreCase) || string.Equals(x.Class, "msDS-ManagedServiceAccount", StringComparison.OrdinalIgnoreCase))))
                    {
                        data.AddDetail("BadPrimaryGroup", GetAccountDetail(x));
                    }
                }
                else
                {
                    // not domain computers & guests
                    if (x.PrimaryGroupID != 515 && x.PrimaryGroupID != 514)
                    {
                        if ((x.PrimaryGroupID == 516 || x.PrimaryGroupID == 521) && x.DistinguishedName.Contains("OU=Domain Controllers,DC="))
                        {
                            // ignore domain controller group
                            // 516 = RW DC, 521 = RO DC
                        }
                        else
                        {
                            data.AddDetail("BadPrimaryGroup", GetAccountDetail(x));
                        }
                    }
                }
                // see [MS-KILE] && https://blogs.msdn.microsoft.com/openspecification/2011/05/30/windows-configurations-for-kerberos-supported-encryption-type/
                // msDSSupportedEncryptionTypes =1 => DES-CBC-CRC ; 2 => DES-CBC-MD5
                // requires at least Windows 2008 / Vista
                if (((x.UserAccountControl & 0x00200000) != 0) || ((x.msDSSupportedEncryptionTypes & (1 | 2)) > 0))
                {
                    data.AddDetail("DesEnabled", GetAccountDetail(x));
                }
                if ((x.UserAccountControl & 0x80000) != 0)
                {
                    data.AddDetail("TrustedToAuthenticateForDelegation", GetAccountDetail(x));
                }
                if ((x.UserAccountControl & 0x0080) != 0)
                {
                    data.AddDetail("ReversibleEncryption", GetAccountDetail(x));
                }
                if (DCWin2008Install != default(DateTime))
                {
                    if ((x.PwdLastSet > new DateTime(1900, 1, 1) && DCWin2008Install > x.PwdLastSet) || (x.PwdLastSet <= new DateTime(1900, 1, 1) && x.WhenCreated.AddHours(1) < DCWin2008Install))
                    {
                        data.AddDetail("NotAesEnabled", GetAccountDetail(x));
                    }
                    else if (x.ServicePrincipalName != null && x.ServicePrincipalName.Length > 0 && !string.IsNullOrEmpty(x.ServicePrincipalName[0]))
                    {
                        // quote: "Users accounts, Group Managed Service accounts, and other accounts in Active Directory do not have the msds-SupportedEncryptionTypes value set automatically. "
                        // https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d#registrykey5021131
                        //if (x.Class != "msds-groupmanagedserviceaccount" && x.Class != "computer" && x.Class != "msds-managedserviceaccount")
                        {
                            if ((x.msDSSupportedEncryptionTypes & (8 + 16)) == 0)
                            {
                                data.AddDetail("NotAesEnabled", GetAccountDetail(x));
                            }
                        }
                    }
                }

            }
            return true;
        }

        private static HealthcheckAccountDetailData GetAccountDetail(ADItem x)
        {
            HealthcheckAccountDetailData data = new HealthcheckAccountDetailData();
            data.DistinguishedName = x.DistinguishedName;
            data.Name = x.SAMAccountName;
            data.CreationDate = x.WhenCreated;
            data.LastLogonDate = x.LastLogonTimestamp;
            data.PwdLastSet = x.PwdLastSet;
            return data;
        }

        public const string computerfilter = "(&(ObjectCategory=computer))";
        public static string[] computerProperties = new string[] {
                        "distinguishedName",
                        "lastLogonTimestamp",
                        "msDS-SupportedEncryptionTypes",
                        "name",
                        "objectClass",
                        "objectSid",
                        "operatingSystem",
                        "operatingSystemVersion",
                        "primaryGroupID",
                        "pwdLastSet",
                        "sAMAccountName",
                        "servicePrincipalName",
                        "sIDHistory",
                        "userAccountControl",
                        "whenCreated",
            };

        private void GenerateComputerData(ADDomainInfo domainInfo, ADWebService adws)
        {

            var LAPSAnalyzer = CheckLAPSInstalled(domainInfo, adws);


            Dictionary<string, HealthcheckOSData> operatingSystems = new Dictionary<string, HealthcheckOSData>();
            Dictionary<string, HealthcheckOSVersionData> operatingSystemVersion = new Dictionary<string, HealthcheckOSVersionData>();

            var lapsDistribution = new Dictionary<int, int>();
            var lapsNewDistribution = new Dictionary<int, int>();

            WorkOnReturnedObjectByADWS callback =
                (ADItem x) =>
                {
                    try
                    {
                        bool isCluster = false;
                        if (x.ServicePrincipalName != null)
                        {
                            foreach (var sp in x.ServicePrincipalName)
                            {
                                if (sp.StartsWith("MSClusterVirtualServer/"))
                                {
                                    isCluster = true;
                                    break;
                                }
                            }
                        }
                        if (isCluster)
                        {
                            // process only not disabled cluster
                            if ((x.UserAccountControl & 0x00000002) == 0)
                            {
                                // cluster created for at least 3 years and use within the last 45 days
                                if (x.WhenCreated.AddYears(3) <= DateTime.Now && x.LastLogonTimestamp.AddDays(45) > DateTime.Now)
                                {
                                    // pwd last set at least 3 years ago
                                    if (x.PwdLastSet.AddYears(3) < x.LastLogonTimestamp)
                                    {
                                        // computer password not changed
                                        if (healthcheckData.ListClusterPwdNotChanged == null)
                                            healthcheckData.ListClusterPwdNotChanged = new List<HealthcheckAccountDetailData>();
                                        healthcheckData.ListClusterPwdNotChanged.Add(GetAccountDetail(x));
                                    }
                                }
                            }
                            // all subsequent checks are to be ignored
                            return;
                        }

                        string os = GetOperatingSystem(x.OperatingSystem);
                        if (!operatingSystems.ContainsKey(os))
                        {
                            operatingSystems[os] = new HealthcheckOSData(os);
                            operatingSystems[os].data = new HealthcheckAccountData();
                            operatingSystems[os].data.DotNotRecordDetail = true;
                        }

                        var proxy = new ProxyHealthcheckAccountData();
                        proxy.Clients.Add(operatingSystems[os].data);
                        proxy.Clients.Add(healthcheckData.ComputerAccountData);

                        if (!string.IsNullOrEmpty(x.OperatingSystemVersion) && x.OperatingSystem != null && x.OperatingSystem.Contains("Windows"))
                        {
                            string key = (x.OperatingSystem.Contains("Server") ? "s" : "w") + "|" + x.OperatingSystemVersion;
                            var isLTSC = x.OperatingSystem.Contains("LTSC") || x.OperatingSystem.Contains("LTSB");
                            if (isLTSC)
                                key += "|LTSC";
                            if (!operatingSystemVersion.ContainsKey(key))
                            {
                                operatingSystemVersion[key] = new HealthcheckOSVersionData(x);
                            }
                            proxy.Clients.Add(operatingSystemVersion[key].data);
                        }

                        if (!ProcessAccountData(proxy, x, true, healthcheckData.DCWin2008Install, healthcheckData.ListHoneyPot))
                            return;

                        // process only not disabled computers
                        if ((x.UserAccountControl & 0x00000002) == 0)
                        {

                            // we consider DC as a computer in the special OU or having the primary group ID of DC or Enterprise DC
                            // known problem: if the DC is a member (not primary group) & not located in the DC OU
                            if (x.DistinguishedName.Contains("OU=Domain Controllers,DC=") || x.PrimaryGroupID == 516 || x.PrimaryGroupID == 521)
                            {
                                healthcheckData.NumberOfDC++;
                                HealthcheckDomainController dc = new HealthcheckDomainController();
                                dc.DCName = x.SAMAccountName.Replace("$", "");
                                dc.CreationDate = x.WhenCreated;
                                // last logon timestam can have a delta of 14 days
                                dc.LastComputerLogonDate = x.LastLogonTimestamp;
                                dc.DistinguishedName = x.DistinguishedName;
                                dc.OperatingSystem = os;
                                dc.OperatingSystemVersion = x.OperatingSystemVersion;

                                dc.PwdLastSet = x.PwdLastSet;
                                if (x.PrimaryGroupID == 521) // RODC
                                {
                                    if ((x.UserAccountControl & 0x05001000) != 0x05001000)
                                    {
                                        dc.RegistrationProblem = "InvalidUserAccount";
                                    }
                                }
                                else // Normal DC
                                {
                                    if ((x.UserAccountControl & 0x00082000) != 0x00082000)
                                    {
                                        dc.RegistrationProblem = "InvalidUserAccount";
                                    }
                                }
                                if (!string.IsNullOrEmpty(healthcheckData.AzureADKerberosSid))
                                {
                                    if (string.Equals(x.ObjectSid.Value, healthcheckData.AzureADKerberosSid, StringComparison.OrdinalIgnoreCase))
                                    {
                                        dc.AzureADKerberos = true;
                                    }
                                }
                                healthcheckData.DomainControllers.Add(dc);
                            }
                            else
                            {
                                if (!string.IsNullOrEmpty(x.OperatingSystem) && x.OperatingSystem.Contains("Server"))
                                {
                                    // this checks excludes the DC because a special case is in place
                                    if (x.WhenCreated.AddDays(45) <= DateTime.Now && x.LastLogonTimestamp.AddDays(45) > DateTime.Now)
                                    {
                                        // computer active for at least 45 days
                                        if (x.PwdLastSet.AddDays(45) < x.LastLogonTimestamp)
                                        {
                                            // computer password not changed
                                            if (healthcheckData.ListComputerPwdNotChanged == null)
                                                healthcheckData.ListComputerPwdNotChanged = new List<HealthcheckAccountDetailData>();
                                            healthcheckData.ListComputerPwdNotChanged.Add(GetAccountDetail(x));
                                        }
                                    }
                                }
                            }
                            if (x.ReplPropertyMetaData != null)
                            {
                                if (LAPSAnalyzer.LegacyLAPSIntId != 0 && x.ReplPropertyMetaData.ContainsKey(LAPSAnalyzer.LegacyLAPSIntId))
                                {
                                    proxy.AddWithoutDetail("LAPS");
                                    var d = x.ReplPropertyMetaData[LAPSAnalyzer.LegacyLAPSIntId];
                                    if (d.LastOriginatingChange != DateTime.MinValue)
                                    {
                                        var i = ConvertDateToKey(d.LastOriginatingChange);
                                        if (lapsDistribution.ContainsKey(i))
                                            lapsDistribution[i]++;
                                        else
                                            lapsDistribution[i] = 1;
                                    }
                                }
                                var newLAPSDate = default(DateTime);
                                // we need this flag because replicationdata may not be accessible and all metadata fields could not be filled
                                bool newLAPSFound = false;
                                if (LAPSAnalyzer.MsLAPSIntId != 0 && x.ReplPropertyMetaData.ContainsKey(LAPSAnalyzer.MsLAPSIntId))
                                {
                                    var d = x.ReplPropertyMetaData[LAPSAnalyzer.MsLAPSIntId].LastOriginatingChange;
                                    if (d > newLAPSDate)
                                        newLAPSDate = d;
                                    newLAPSFound = true;
                                }
                                if (LAPSAnalyzer.MsLAPSEncryptedIntId != 0 && x.ReplPropertyMetaData.ContainsKey(LAPSAnalyzer.MsLAPSEncryptedIntId))
                                {
                                    var d = x.ReplPropertyMetaData[LAPSAnalyzer.MsLAPSEncryptedIntId].LastOriginatingChange;
                                    if (d > newLAPSDate)
                                        newLAPSDate = d;
                                    newLAPSFound = true;
                                }
                                if (newLAPSFound)
                                    proxy.AddWithoutDetail("LAPSNew");

                                if (newLAPSDate != default(DateTime))
                                {
                                    var i = ConvertDateToKey(newLAPSDate);
                                    if (lapsNewDistribution.ContainsKey(i))
                                        lapsNewDistribution[i]++;
                                    else
                                        lapsNewDistribution[i] = 1;

                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Trace.WriteLine("Exception while working on " + x.DistinguishedName);
                        DisplayAdvancementWarning("Exception while working on " + x.DistinguishedName + "(" + ex.Message + ")");
                        DisplayContactSupport();
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine(ex.StackTrace);
                        Console.ResetColor();
                        Trace.WriteLine(ex.ToString());
                    }
                };


            var computerPropertiesList = new List<string>(computerProperties);

            if (LAPSAnalyzer.LAPSInstalled)
            {
                computerPropertiesList.Add("replPropertyMetaData");
            }

            adws.Enumerate(() =>
                {
                    healthcheckData.ComputerAccountData = new HealthcheckAccountData();
                    healthcheckData.DomainControllers = new List<HealthcheckDomainController>();
                    healthcheckData.OperatingSystem = new List<HealthcheckOSData>();
                    healthcheckData.OperatingSystemVersion = new List<HealthcheckOSVersionData>();
                    operatingSystems.Clear();
                    operatingSystemVersion.Clear();
                },
                domainInfo.DefaultNamingContext, computerfilter, computerPropertiesList.ToArray(), callback, "SubTree");

            foreach (string key in operatingSystems.Keys)
            {
                operatingSystems[key].NumberOfOccurence = operatingSystems[key].data.NumberActive;
                healthcheckData.OperatingSystem.Add(operatingSystems[key]);
            }
            foreach (string key in operatingSystemVersion.Keys)
            {
                operatingSystemVersion[key].NumberOfOccurence = operatingSystemVersion[key].data.NumberActive;
                healthcheckData.OperatingSystemVersion.Add(operatingSystemVersion[key]);
            }

            healthcheckData.LapsDistribution = new List<HealthcheckPwdDistributionData>();
            healthcheckData.LapsNewDistribution = new List<HealthcheckPwdDistributionData>();

            foreach (var p in lapsDistribution)
            {
                healthcheckData.LapsDistribution.Add(new HealthcheckPwdDistributionData() { HigherBound = p.Key, Value = p.Value });
            }
            foreach (var p in lapsNewDistribution)
            {
                healthcheckData.LapsNewDistribution.Add(new HealthcheckPwdDistributionData() { HigherBound = p.Key, Value = p.Value });
            }
        }

        static private void ProcessSIDHistory(ADItem x, IAddAccountData data)
        {
            if (x.SIDHistory != null && x.SIDHistory.Length > 0)
            {
                data.AddSIDHistoryDetail(GetAccountDetail(x), x);
            }
        }

        private void GenerateGroupSidHistoryData(ADDomainInfo domainInfo, ADWebService adws)
        {
            string[] properties = new string[] {
                        "distinguishedName",
                        "sIDHistory",
                        "WhenCreated",
            };
            Trace.WriteLine("checking sid history for groups");
            int count = 0;
            WorkOnReturnedObjectByADWS callback =
                (ADItem x) =>
                {
                    ProcessSIDHistory(x, healthcheckData.UserAccountData);
                    count++;
                };
            string groupselection = "(|(|(|(objectClass=posixGroup)(objectClass=groupOfUniqueNames))(objectClass=groupOfNames))(objectClass=group))";
            adws.Enumerate(domainInfo.DefaultNamingContext, "(&(sidhistory=*)" + groupselection + ")", properties, callback);
            Trace.WriteLine("Having found " + count + " groups with sid history");
        }

        public static string GetOperatingSystem(string os)
        {
            if (string.IsNullOrEmpty(os))
            {
                return "OperatingSystem not set";
            }

            os = os.Replace('\u00A0', ' ');

            var osPatterns = new Dictionary<string, string>
            {
                { @"windows(.*) 2000", "Windows 2000" },
                { @"windows server(.*) 2003", "Windows 2003" },
                { @"windows server(.*) 2008", "Windows 2008" },
                { @"windows server(.*) 2012", "Windows 2012" },
                { @"windows server(.*) 2016", "Windows 2016" },
                { @"windows server(.*) 2019", "Windows 2019" },
                { @"windows server(.*) 2022", "Windows 2022" },
                { @"windows server(.*) 2025", "Windows 2025" },
                { @"windows(.*) Embedded", "Windows Embedded" },
                { @"windows(.*) 7", "Windows 7" },
                { @"windows(.*) 8", "Windows 8" },
                { @"windows(.*) XP", "Windows XP" },
                { @"windows(.*) 10", "Windows 10" },
                { @"windows(.*) 11", "Windows 11" },
                { @"windows(.*) Vista", "Windows Vista" },
                { @"windows(.*) NT", "Windows NT" },
            };

            foreach (var pattern in osPatterns)
            {
                if (Regex.IsMatch(os, pattern.Key, RegexOptions.IgnoreCase))
                {
                    return pattern.Value;
                }
            }

            return os;
        }


        private void GenerateTrustData(ADDomainInfo domainInfo, ADWebService adws)
        {
            healthcheckData.Trusts = new List<HealthCheckTrustData>();
            string[] properties = new string[] {
                        "distinguishedName",
                        "securityIdentifier",
                        "trustPartner",
                        "trustAttributes",
                        "trustDirection",
                        "trustType",
                        "whenCreated",
                        "whenChanged",
                        "msDS-TrustForestTrustInfo",
                        "msDS-SupportedEncryptionTypes",
            };
            DomainLocator dl = new DomainLocator(domainInfo.DnsHostName);

            WorkOnReturnedObjectByADWS callback =
                (ADItem x) =>
                {
                    HealthCheckTrustData trust = new HealthCheckTrustData();
                    healthcheckData.Trusts.Add(trust);
                    trust.TrustPartner = x.TrustPartner.ToLowerInvariant();
                    trust.TrustAttributes = x.TrustAttributes;
                    trust.TrustDirection = x.TrustDirection;
                    trust.TrustType = x.TrustType;
                    trust.CreationDate = x.WhenCreated;
                    trust.msDSSupportedEncryptionTypes = x.msDSSupportedEncryptionTypes;
                    // if a trust is active, the password is changed every 30 days
                    // so the object will be changed
                    trust.IsActive = (x.WhenChanged.AddDays(40) > DateTime.Now);
                    // sid is used to translate unknown FSP
                    if (x.SecurityIdentifier != null)
                    {
                        trust.SID = x.SecurityIdentifier.Value;
                    }
                    if (x.msDSTrustForestTrustInfo != null)
                    {
                        trust.KnownDomains = x.msDSTrustForestTrustInfo;
                        // remove the trustpartner from the domain infos
                        foreach (HealthCheckTrustDomainInfoData di in trust.KnownDomains)
                        {
                            di.ForestName = x.TrustPartner;
                            di.ForestSid = trust.SID;
                        }
                        foreach (HealthCheckTrustDomainInfoData di in trust.KnownDomains)
                        {
                            if (di.DnsName == x.TrustPartner)
                            {
                                trust.KnownDomains.Remove(di);
                                break;
                            }
                        }
                        if (trust.KnownDomains.Count == 0)
                            trust.KnownDomains = null;
                    }
                    string netbios, forest;
                    if (dl.LocateNetbiosFromFQDN(trust.TrustPartner, out netbios, out forest))
                    {
                        trust.NetBiosName = netbios;
                        // copy the netbios info to the forest trust info
                        if (trust.KnownDomains != null)
                        {
                            foreach (HealthCheckTrustDomainInfoData di in trust.KnownDomains)
                            {
                                di.ForestNetbios = trust.NetBiosName;
                            }
                        }
                        // if the trusted domain is part of a forest, add it
                        if (domainInfo.ForestName != domainInfo.DomainName
                            && !trust.TrustPartner.Equals(domainInfo.ForestName, StringComparison.InvariantCultureIgnoreCase)
                            && !forest.Equals(trust.TrustPartner, StringComparison.InvariantCultureIgnoreCase))
                        {
                            trust.KnownDomains = new List<HealthCheckTrustDomainInfoData>();
                            HealthCheckTrustDomainInfoData data = new HealthCheckTrustDomainInfoData();
                            data.DnsName = forest;
                            data.CreationDate = DateTime.MinValue;
                            data.ForestName = forest;
                            SecurityIdentifier sid = adws.ConvertNameToSID(forest);
                            if (sid != null)
                            {
                                data.Sid = sid.Value;
                                data.ForestSid = data.Sid;
                            }
                            if (dl.LocateNetbiosFromFQDN(forest, out netbios, out forest))
                            {
                                data.NetbiosName = netbios;
                            }
                            trust.KnownDomains.Add(data);
                        }
                    }
                };
            // enumerate trustedDomain objects
            adws.Enumerate(domainInfo.DefaultNamingContext, "(ObjectCategory=trustedDomain)", properties, callback);

            if (domainInfo.ForestName != domainInfo.DomainName)
            {
                HealthCheckTrustData forestTrust = null;
                // enumerate child domains found in configuration
                // we do this in case we can access only this domain through a trust and not the whole forest
                foreach (HealthCheckTrustData trust in healthcheckData.Trusts)
                {
                    if (trust.TrustPartner != null
                        && trust.TrustPartner.Equals(domainInfo.ForestName, StringComparison.InvariantCultureIgnoreCase))
                    {
                        forestTrust = trust;
                        break;
                    }
                }
                if (forestTrust != null)
                {
                    if (forestTrust.KnownDomains == null)
                        forestTrust.KnownDomains = new List<HealthCheckTrustDomainInfoData>();
                    string[] propertiesCrossRefDomains = new string[] { "dnsRoot", "nETBIOSName", "whenCreated" };
                    WorkOnReturnedObjectByADWS callbackCrossRef =
                    (ADItem x) =>
                    {
                        if (x.DnsRoot.Equals(domainInfo.DomainName, StringComparison.InvariantCultureIgnoreCase)
                            || x.DnsRoot.Equals(domainInfo.ForestName, StringComparison.InvariantCultureIgnoreCase))
                        {
                            return;
                        }
                        HealthCheckTrustDomainInfoData data = new HealthCheckTrustDomainInfoData();
                        forestTrust.KnownDomains.Add(data);
                        data.DnsName = x.DnsRoot;
                        data.NetbiosName = x.NetBIOSName;
                        data.CreationDate = x.WhenCreated;
                        data.ForestName = domainInfo.ForestName;
                        data.ForestNetbios = forestTrust.NetBiosName;
                        data.ForestSid = forestTrust.SID;
                        SecurityIdentifier sid = adws.ConvertNameToSID(x.DnsRoot);
                        if (sid != null)
                            data.Sid = sid.Value;
                    };
                    adws.Enumerate("CN=Partitions," + domainInfo.ConfigurationNamingContext,
                                                    "(&(objectCategory=crossRef)(systemFlags:1.2.840.113556.1.4.803:=3)(dnsRoot=*))",
                                                    propertiesCrossRefDomains, callbackCrossRef, "OneLevel");
                    if (forestTrust.KnownDomains.Count == 0)
                        forestTrust.KnownDomains = null;
                }
            }
            // add information about trust info
            if (healthcheckData.UserAccountData != null && healthcheckData.UserAccountData.ListDomainSidHistory != null)
            {
                EnrichSIDHistoryWithTrustData(healthcheckData.UserAccountData.ListDomainSidHistory);
            }
            if (healthcheckData.ComputerAccountData != null && healthcheckData.ComputerAccountData.ListDomainSidHistory != null)
            {
                EnrichSIDHistoryWithTrustData(healthcheckData.ComputerAccountData.ListDomainSidHistory);
            }

            // process AzureAD SSO
            string[] AzureAccountproperties = new string[] {
                        "distinguishedName",
                        "securityIdentifier",
                        "msDS-SupportedEncryptionTypes",
                        "pwdLastSet",
                        "replPropertyMetaData",
                        "whenCreated",
            };
            WorkOnReturnedObjectByADWS callbackAzureAccount =
                    (ADItem x) =>
                    {
                        DateTime d = x.WhenCreated;
                        if (x.PwdLastSet > d)
                        {
                            d = x.PwdLastSet;
                        }
                        else////////////
                        {
                            if (x.ReplPropertyMetaData != null && d < x.ReplPropertyMetaData[0x9005A].LastOriginatingChange)
                            {
                                d = x.ReplPropertyMetaData[0x9005A].LastOriginatingChange;
                                healthcheckData.AzureADSSOVersion = x.ReplPropertyMetaData[0x9005A].Version;
                            }
                        }
                        healthcheckData.AzureADSSOEncryptionType = x.msDSSupportedEncryptionTypes;
                        healthcheckData.AzureADSSOLastPwdChange = d;
                    };

            adws.Enumerate(domainInfo.DefaultNamingContext, "(SamAccountName=AZUREADSSOACC$)", AzureAccountproperties, callbackAzureAccount);
        }

        private void EnrichSIDHistoryWithTrustData(IList<HealthcheckSIDHistoryData> list)
        {
            foreach (HealthcheckSIDHistoryData data in list)
            {
                foreach (HealthCheckTrustData trustdata in healthcheckData.Trusts)
                {
                    // if the infomration is found and TrustData and KnownDomain, TrustData has the priority
                    if (trustdata.SID == data.DomainSid)
                    {
                        data.FriendlyName = trustdata.TrustPartner;
                        data.NetBIOSName = trustdata.NetBiosName;
                        break;
                    }
                    if (trustdata.KnownDomains != null)
                    {
                        foreach (HealthCheckTrustDomainInfoData trustdomainInfo in trustdata.KnownDomains)
                        {
                            if (trustdomainInfo.Sid == data.DomainSid)
                            {
                                data.FriendlyName = trustdomainInfo.DnsName;
                                data.NetBIOSName = trustdomainInfo.NetbiosName;
                                break;
                            }
                        }
                    }
                }
                if (data.DomainSid == healthcheckData.DomainSid)
                {
                    data.FriendlyName = healthcheckData.DomainFQDN;
                    data.NetBIOSName = healthcheckData.NetBIOSName;
                }
                if (String.IsNullOrEmpty(data.FriendlyName))
                    data.FriendlyName = data.DomainSid;
            }
        }

        private void GenerateReachableTrustData(ADDomainInfo domainInfo, ADWebService adws)
        {
            // prepare a list of all SID that doesn't belong to the domain nor to a known trust
            // foreign security principals
            List<SecurityIdentifier> UnknownSids = GetExternalFSPDomainSids(domainInfo, adws);
            UnknownSids = FilterKnownDomains(UnknownSids);
            // sid history data
            if (healthcheckData.UserAccountData != null && healthcheckData.UserAccountData.ListDomainSidHistory != null)
            {
                foreach (HealthcheckSIDHistoryData data in healthcheckData.UserAccountData.ListDomainSidHistory)
                {
                    if (data.FriendlyName.StartsWith("S-1-", StringComparison.InvariantCultureIgnoreCase))
                    {
                        UnknownSids.Add(new SecurityIdentifier(data.DomainSid));
                    }
                }
            }
            if (healthcheckData.ComputerAccountData != null && healthcheckData.ComputerAccountData.ListDomainSidHistory != null)
            {
                foreach (HealthcheckSIDHistoryData data in healthcheckData.ComputerAccountData.ListDomainSidHistory)
                {
                    if (data.FriendlyName.StartsWith("S-1-", StringComparison.InvariantCultureIgnoreCase))
                    {
                        UnknownSids.Add(new SecurityIdentifier(data.DomainSid));
                    }
                }
            }
            DomainLocator dl = new DomainLocator(domainInfo.DnsHostName);
            // discovering reachable domains by resolving the SID by the domain
            foreach (SecurityIdentifier domainSid in UnknownSids)
            {
                string name = adws.ConvertSIDToName(domainSid.Value);
                // name resolved
                if (name.Contains("\\"))
                {
                    string[] values = name.Split('\\');
                    HealthCheckTrustDomainInfoData data = new HealthCheckTrustDomainInfoData();
                    data.Sid = domainSid.Value;
                    data.DnsName = values[0];
                    data.NetbiosName = values[0];
                    data.CreationDate = DateTime.MinValue;
                    if (healthcheckData.ReachableDomains == null)
                        healthcheckData.ReachableDomains = new List<HealthCheckTrustDomainInfoData>();
                    healthcheckData.ReachableDomains.Add(data);
                    string fqdn, forestname;
                    if (dl.LocateDomainFromNetbios(data.NetbiosName, out fqdn, out forestname))
                    {
                        data.DnsName = fqdn;
                        data.ForestName = forestname;
                        if (!forestname.Equals(data.DnsName, StringComparison.InvariantCultureIgnoreCase))
                        {
                            SecurityIdentifier sid = adws.ConvertNameToSID(forestname);
                            if (sid != null)
                                data.ForestSid = sid.Value;
                            string netbios;
                            if (dl.LocateNetbiosFromFQDN(forestname, out netbios, out forestname))
                            {
                                data.ForestNetbios = netbios;
                            }
                        }
                    }
                }
            }
            // enrich SID History data
            if (healthcheckData.ReachableDomains != null)
            {
                if (healthcheckData.UserAccountData != null && healthcheckData.UserAccountData.ListDomainSidHistory != null)
                {
                    foreach (HealthcheckSIDHistoryData data in healthcheckData.UserAccountData.ListDomainSidHistory)
                    {
                        if (data.FriendlyName.StartsWith("S-1-", StringComparison.InvariantCultureIgnoreCase))
                        {
                            foreach (HealthCheckTrustDomainInfoData di in healthcheckData.ReachableDomains)
                            {
                                if (di.Sid.Equals(data.FriendlyName, StringComparison.InvariantCultureIgnoreCase))
                                {
                                    data.FriendlyName = di.DnsName;
                                    break;
                                }
                            }
                        }
                    }
                }
                if (healthcheckData.ComputerAccountData != null && healthcheckData.ComputerAccountData.ListDomainSidHistory != null)
                {
                    foreach (HealthcheckSIDHistoryData data in healthcheckData.ComputerAccountData.ListDomainSidHistory)
                    {
                        if (data.FriendlyName.StartsWith("S-1-", StringComparison.InvariantCultureIgnoreCase))
                        {
                            foreach (HealthCheckTrustDomainInfoData di in healthcheckData.ReachableDomains)
                            {
                                if (di.Sid.Equals(data.FriendlyName, StringComparison.InvariantCultureIgnoreCase))
                                {
                                    data.FriendlyName = di.DnsName;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        private List<SecurityIdentifier> GetExternalFSPDomainSids(ADDomainInfo domainInfo, ADWebService adws)
        {
            string[] properties = new string[] {
                        "name",
            };
            string filter = "(name=S-1-5-21-*)";
            List<SecurityIdentifier> externalDomainSids = new List<SecurityIdentifier>();
            WorkOnReturnedObjectByADWS callback =
                (ADItem x) =>
                {
                    // beware: can have replicated pb on FSP => SID end with cnf string and should be discarded
                    string sidPattern = @"^S-\d-\d+-(\d+-){1,14}\d+$";
                    bool isValidFormat = Regex.IsMatch(x.Name, sidPattern);
                    if (isValidFormat)
                    {
                        SecurityIdentifier domainSid = new SecurityIdentifier(x.Name).AccountDomainSid;
                        if (!externalDomainSids.Contains(domainSid))
                            externalDomainSids.Add(domainSid);
                    }
                };
            adws.Enumerate("CN=ForeignSecurityPrincipals," + domainInfo.DefaultNamingContext, filter, properties, callback, "OneLevel");
            return externalDomainSids;
        }

        private List<SecurityIdentifier> FilterKnownDomains(List<SecurityIdentifier> domainSidsToFilter)
        {
            List<SecurityIdentifier> output = new List<SecurityIdentifier>();
            if (healthcheckData.Trusts == null)
                return output;
            foreach (SecurityIdentifier domainSid in domainSidsToFilter)
            {
                bool found = false;
                foreach (HealthCheckTrustData trust in healthcheckData.Trusts)
                {
                    if (!String.IsNullOrEmpty(trust.SID) && new SecurityIdentifier(trust.SID) == domainSid)
                    {
                        found = true;
                        break;
                    }
                    if (trust.KnownDomains != null)
                    {
                        foreach (HealthCheckTrustDomainInfoData di in trust.KnownDomains)
                        {
                            if (!String.IsNullOrEmpty(di.Sid) && new SecurityIdentifier(di.Sid) == domainSid)
                            {
                                found = true;
                                break;
                            }
                        }
                        if (found)
                            break;
                    }
                }
                if (!found)
                    output.Add(domainSid);
            }
            return output;
        }

        private void GeneratePrivilegedGroupAndPermissionsData(ADDomainInfo domainInfo, ADWebService adws, PingCastleAnalyzerParameters parameters)
        {
            var generator = new ReportGenerator();
            generator.PerformAnalyze(healthcheckData, domainInfo, adws, parameters);
            // compute other analyses
            // distribution
            healthcheckData.PrivilegedDistributionLastLogon = new List<HealthcheckPwdDistributionData>();
            healthcheckData.PrivilegedDistributionPwdLastSet = new List<HealthcheckPwdDistributionData>();

            var pwdDistribution = new Dictionary<int, int>();
            var logonDistribution = new Dictionary<int, int>();
            foreach (var user in healthcheckData.AllPrivilegedMembers)
            {
                if (user.IsEnabled)
                {
                    {
                        var i = ConvertDateToKey(user.PwdLastSet == DateTime.MinValue ? user.Created : user.PwdLastSet);

                        if (pwdDistribution.ContainsKey(i))
                            pwdDistribution[i]++;
                        else
                            pwdDistribution[i] = 1;
                    }
                    if (user.LastLogonTimestamp != DateTime.MinValue)
                    {
                        var i = ConvertDateToKey(user.LastLogonTimestamp);

                        if (logonDistribution.ContainsKey(i))
                            logonDistribution[i]++;
                        else
                            logonDistribution[i] = 1;
                    }
                }
            }
            foreach (var p in logonDistribution)
            {
                healthcheckData.PrivilegedDistributionLastLogon.Add(new HealthcheckPwdDistributionData() { HigherBound = p.Key, Value = p.Value });
            }
            foreach (var p in pwdDistribution)
            {
                healthcheckData.PrivilegedDistributionPwdLastSet.Add(new HealthcheckPwdDistributionData() { HigherBound = p.Key, Value = p.Value });
            }
        }

        private void GenerateDelegationData(ADDomainInfo domainInfo, ADWebService adws)
        {
            healthcheckData.Delegations = new List<HealthcheckDelegationData>();
            healthcheckData.UnprotectedOU = new List<string>();
            InspectAdminSDHolder(domainInfo, adws);
            InspectDelegation(domainInfo, adws);
        }

        // SDDL reference from MSDN based on schema version 35 and next
        static string sddlReference = "D:PAI(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;CA)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)(OA;;RPWP;6db69a1c-9422-11d1-aebd-0000f80367c1;;S-1-5-32-561)(OA;;RPWP;5805bc62-bdc9-4428-a5e2-856a0f4c185e;;S-1-5-32-561)(OA;;LCRPLORC;;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;LCRPLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;PS)(OA;CI;RPWPCR;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;PS)(A;;CCDCLCSWRPWPLOCRRCWDWO;;;DA)(A;;CCDCLCSWRPWPLOCRRCWDWO;;;EA)(A;;CCDCLCSWRPWPLOCRSDRCWDWO;;;BA)(A;;LCRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)";
        private void InspectAdminSDHolder(ADDomainInfo domainInfo, ADWebService adws)
        {
            string[] properties = new string[] {
                        "distinguishedName",
                        "name",
                        "nTSecurityDescriptor",
            };
            ActiveDirectorySecurity AdminSDHolder = null;
            WorkOnReturnedObjectByADWS callback =
                (ADItem x) =>
                {
                    AdminSDHolder = x.NTSecurityDescriptor;
                };

            adws.Enumerate(domainInfo.DefaultNamingContext, "(distinguishedName=CN=AdminSDHolder,CN=System," + domainInfo.DefaultNamingContext + ")", properties, callback);

            if (AdminSDHolder != null)
            {
                ActiveDirectorySecurity reference = new ActiveDirectorySecurity();
                string sddlToCheck = AdminSDHolder.GetSecurityDescriptorSddlForm(AccessControlSections.Access);
                //reference.SetSecurityDescriptorSddlForm(AdminSDHolderSDDL44);
                List<string> rulesAdded = CompareSecurityDescriptor(sddlToCheck, sddlReference, domainInfo.DomainSid);
                AddAdminSDHolderSDDLRulesToDelegation(adws, rulesAdded, domainInfo);
            }
            else
            {
                HealthcheckDelegationData data = new HealthcheckDelegationData();
                data.DistinguishedName = "AdminSDHolder";
                data.Account = "Authenticated Users";
                data.Right = "Not allowed to read AdminSDHolder";
                data.SecurityIdentifier = string.Empty;
            }
        }

        private void AddAdminSDHolderSDDLRulesToDelegation(ADWebService adws, List<string> rulesAdded, ADDomainInfo domainInfo)
        {
            Dictionary<string, string> dic = new Dictionary<string, string>();
            foreach (string rule in rulesAdded)
            {
                string[] SDDL = rule.Split(';');
                if (SDDL.Length < 6)
                    continue;
                string sid = SDDL[5];
                if (sid.StartsWith("S-1-5-21"))
                {
                    if (!dic.ContainsKey(sid))
                        dic[sid] = "Rule in AdminSDHolder (modified or added)";
                }
            }
            foreach (string key in dic.Keys)
            {
                HealthcheckDelegationData data = new HealthcheckDelegationData();
                data.DistinguishedName = "AdminSDHolder";
                data.SecurityIdentifier = key;
                data.Account = adws.ConvertSIDToName(key);
                data.Right = dic[key];
                healthcheckData.Delegations.Add(data);
            }
        }

        private List<string> CompareSecurityDescriptor(string sddlToCheck, string sddlReference, SecurityIdentifier domain)
        {
            List<string> output = new List<string>();
            sddlToCheck = sddlToCheck.Substring(5);
            sddlReference = sddlReference.Substring(5);
            sddlToCheck = sddlToCheck.Replace(new SecurityIdentifier(WellKnownSidType.AccountDomainAdminsSid, domain).Value, "DA");
            sddlToCheck = Regex.Replace(sddlToCheck, @"S-1-5-21-\d+-\d+-\d+-519", "EA");
            //sddlToCheck = sddlToCheck.Replace(new SecurityIdentifier(WellKnownSidType.AccountEnterpriseAdminsSid, domain).Value, "EA");
            sddlToCheck = sddlToCheck.Replace(new SecurityIdentifier(WellKnownSidType.AccountCertAdminsSid, domain).Value, "CA");

            string[] values = sddlToCheck.Split(new string[] { "(", ")" }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string value in values)
            {
                if (!sddlReference.Contains("(" + value + ")"))
                {
                    output.Add(value);
                    Trace.WriteLine("AdminSDHolder unknown entry:" + value);
                }
            }
            return output;
        }


        private void InspectDelegation(ADDomainInfo domainInfo, ADWebService adws)
        {
            var lapsAnalyzer = new LAPSAnalyzer(adws);
            if (lapsAnalyzer.LegacyLAPSSchemaId != Guid.Empty)
                ReadGuidsControlProperties.Add(new KeyValuePair<Guid, string>(lapsAnalyzer.LegacyLAPSSchemaId, "READ_PROP_ms-mcs-admpwd"));
            if (lapsAnalyzer.MsLAPSSchemaId != Guid.Empty)
                ReadGuidsControlProperties.Add(new KeyValuePair<Guid, string>(lapsAnalyzer.MsLAPSSchemaId, "READ_PROP_ms-LAPS-Password"));
            if (lapsAnalyzer.MsLAPSEncryptedSchemaId != Guid.Empty)
                ReadGuidsControlProperties.Add(new KeyValuePair<Guid, string>(lapsAnalyzer.MsLAPSEncryptedSchemaId, "READ_PROP_ms-LAPS-EncryptedPassword"));

            string[] properties = new string[] {
                        "distinguishedName",
                        "name",
                        "nTSecurityDescriptor",
                        "objectClass",
            };
            Dictionary<string, string> sidCache = new Dictionary<string, string>();
            WorkOnReturnedObjectByADWS callback =
                (ADItem x) =>
                {
                    var delegations = BuildDelegationList(adws, sidCache, x);
                    healthcheckData.Delegations.AddRange(delegations);

                    if (string.Equals(x.Class, "organizationalUnit", StringComparison.InvariantCultureIgnoreCase))
                    {
                        bool isProtected = false;
                        ActiveDirectorySecurity sd = x.NTSecurityDescriptor;
                        if (sd == null)
                            return;
                        foreach (ActiveDirectoryAccessRule accessrule in sd.GetAccessRules(true, false, typeof(SecurityIdentifier)))
                        {
                            // ignore audit / denied ace
                            if (accessrule.AccessControlType != AccessControlType.Deny)
                                continue;
                            if ((accessrule.ActiveDirectoryRights & ActiveDirectoryRights.Delete) == 0)
                                continue;
                            if ((accessrule.ActiveDirectoryRights & ActiveDirectoryRights.DeleteTree) == 0)
                                continue;
                            var id = (SecurityIdentifier)accessrule.IdentityReference;
                            if (id.Value != "S-1-1-0")
                                continue;
                            isProtected = true;
                        }
                        if (!isProtected)
                        {
                            healthcheckData.UnprotectedOU.Add(x.DistinguishedName);
                        }
                    }
                };

            adws.Enumerate(
                () =>
                {
                    healthcheckData.Delegations.Clear();
                    healthcheckData.UnprotectedOU.Clear();
                },
                domainInfo.DefaultNamingContext, "(|(objectCategory=organizationalUnit)(objectCategory=container)(objectCategory=domain)(objectCategory=buitinDomain))", properties, callback, "SubTree");

            adws.Enumerate(domainInfo.ConfigurationNamingContext, "(objectCategory=configuration)", properties, callback, "Base");
        }

        // removed unexpire password because permissions given to authenticated users at the root of the domain
        static KeyValuePair<Guid, string>[] GuidsControlExtendedRights = new KeyValuePair<Guid, string>[] {
                    new KeyValuePair<Guid, string>(new Guid("00299570-246d-11d0-a768-00aa006e0529"), "EXT_RIGHT_FORCE_CHANGE_PWD"),
                    new KeyValuePair<Guid, string>(new Guid("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"), "EXT_RIGHT_REPLICATION_GET_CHANGES_ALL"),
                    new KeyValuePair<Guid, string>(new Guid("45ec5156-db7e-47bb-b53f-dbeb2d03c40f"), "EXT_RIGHT_REANIMATE_TOMBSTONE"),
//                    new KeyValuePair<Guid, string>(new Guid("ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501"), "EXT_RIGHT_UNEXPIRE_PASSWORD"),
//                    new KeyValuePair<Guid, string>(new Guid("ba33815a-4f93-4c76-87f3-57574bff8109"), "EXT_RIGHT_MIGRATE_SID_HISTORY"),
                };

        static KeyValuePair<Guid, string>[] GuidsControlValidatedWrites = new KeyValuePair<Guid, string>[] {
                        new KeyValuePair<Guid, string>(new Guid("bc0ac240-79a9-11d0-9020-00c04fc2d4cf"),"WRITE_PROPSET_MEMBERSHIP"),
                    };

        List<KeyValuePair<Guid, string>> GuidsControlProperties = new List<KeyValuePair<Guid, string>>{
                        new KeyValuePair<Guid, string>(new Guid("bf9679c0-0de6-11d0-a285-00aa003049e2"),"WRITE_PROP_MEMBER"),
                        new KeyValuePair<Guid, string>(new Guid("f30e3bbe-9ff0-11d1-b603-0000f80367c1"),"WRITE_PROP_GPLINK"),
                        new KeyValuePair<Guid, string>(new Guid("f30e3bc1-9ff0-11d0-b603-0000f80367c1"),"WRITE_PROP_GPC_FILE_SYS_PATH"),
                    };
        List<KeyValuePair<Guid, string>> ReadGuidsControlProperties = new List<KeyValuePair<Guid, string>>
        {
        };
        static KeyValuePair<Guid, string>[] GuidsControlPropertiesSets = new KeyValuePair<Guid, string>[] {
                        new KeyValuePair<Guid, string>(new Guid("bf9679c0-0de6-11d0-a285-00aa003049e2"),"VAL_WRITE_SELF_MEMBERSHIP"),
                    };

        Guid EnrollPermission = new Guid("0e10c968-78fb-11d2-90d4-00c04f79dc55");
        Guid AutoEnrollPermission = new Guid("a05b8cc2-17bc-4802-a710-e7c15ab866a2");

        delegate void WorkOnDelegation(SecurityIdentifier sid, string right);

        void FilterAdminSDHolder(ADItem x, WorkOnDelegation gotDelegation)
        {
            ActiveDirectorySecurity sd = x.NTSecurityDescriptor;
            if (sd == null)
                return;
            // check the owner
            SecurityIdentifier owner = (SecurityIdentifier)sd.GetOwner(typeof(SecurityIdentifier));
            if (!owner.IsWellKnown(WellKnownSidType.AccountDomainAdminsSid))
            {
                gotDelegation(owner, "OWNER");
            }
            foreach (ActiveDirectoryAccessRule accessrule in sd.GetAccessRules(true, false, typeof(SecurityIdentifier)))
            {
                if (accessrule.AccessControlType != AccessControlType.Allow)
                    continue;
                SecurityIdentifier si = (SecurityIdentifier)accessrule.IdentityReference;
                // SYSTEM
                if (si.Value == "S-1-5-18")
                    continue;
                // DS SELF
                if (si.Value == "S-1-3-0")
                    continue;
                // build in admin
                if (si.Value == "S-1-5-32-544")
                    continue;

                if (si.IsWellKnown(WellKnownSidType.AccountDomainAdminsSid))
                    continue;
                if (si.IsWellKnown(WellKnownSidType.AccountEnterpriseAdminsSid))
                    continue;

                Trace.WriteLine(si.Value);
                Trace.WriteLine(accessrule.ActiveDirectoryRights);
                Trace.WriteLine(accessrule.ObjectType);
                Trace.WriteLine(accessrule.InheritedObjectType);
                Trace.WriteLine(accessrule.ObjectFlags);
            }
        }

        void FilterDelegation(ADItem x, WorkOnDelegation gotDelegation)
        {
            ActiveDirectorySecurity sd = x.NTSecurityDescriptor;
            if (sd == null)
                return;
            foreach (ActiveDirectoryAccessRule accessrule in sd.GetAccessRules(true, false, typeof(SecurityIdentifier)))
            {
                // ignore audit / denied ace
                if (accessrule.AccessControlType != AccessControlType.Allow)
                    continue;
                SecurityIdentifier si = (SecurityIdentifier)accessrule.IdentityReference;
                // SYSTEM
                if (si.Value == "S-1-5-18")
                    continue;
                // DS SELF
                if (si.Value == "S-1-3-0")
                    continue;
                // build in admin
                if (si.Value == "S-1-5-32-544")
                    continue;
                // ENTERPRISE_DOMAIN_CONTROLLERS
                if (si.Value == "S-1-5-9")
                    continue;

                if (si.IsWellKnown(WellKnownSidType.AccountDomainAdminsSid))
                    continue;
                if (si.IsWellKnown(WellKnownSidType.AccountEnterpriseAdminsSid))
                    continue;

                // ADS_RIGHT_GENERIC_ALL
                if ((accessrule.ActiveDirectoryRights & ActiveDirectoryRights.GenericAll) == ActiveDirectoryRights.GenericAll)
                {
                    gotDelegation((SecurityIdentifier)accessrule.IdentityReference, "GenericAll");
                }
                // ADS_RIGHT_GENERIC_WRITE
                if ((accessrule.ActiveDirectoryRights & ActiveDirectoryRights.GenericWrite) == ActiveDirectoryRights.GenericWrite)
                {
                    gotDelegation((SecurityIdentifier)accessrule.IdentityReference, "GenericWrite");
                }
                // ADS_RIGHT_WRITE_DAC
                if ((accessrule.ActiveDirectoryRights & ActiveDirectoryRights.WriteDacl) == ActiveDirectoryRights.WriteDacl)
                {
                    gotDelegation((SecurityIdentifier)accessrule.IdentityReference, "WriteDacl");
                }
                // ADS_RIGHT_WRITE_OWNER
                if ((accessrule.ActiveDirectoryRights & ActiveDirectoryRights.WriteOwner) == ActiveDirectoryRights.WriteOwner)
                {
                    gotDelegation((SecurityIdentifier)accessrule.IdentityReference, "WriteOwner");
                }
                if (accessrule.ObjectFlags == ObjectAceFlags.None)
                {
                    // ADS_RIGHT_DS_CONTROL_ACCESS
                    if ((accessrule.ActiveDirectoryRights & ActiveDirectoryRights.ExtendedRight) == ActiveDirectoryRights.ExtendedRight)
                    {
                        gotDelegation((SecurityIdentifier)accessrule.IdentityReference, "All extended right");
                    }
                    // ADS_RIGHT_DS_SELF
                    if ((accessrule.ActiveDirectoryRights & ActiveDirectoryRights.Self) == ActiveDirectoryRights.Self)
                    {
                        gotDelegation((SecurityIdentifier)accessrule.IdentityReference, "DSSelf");
                    }
                    // ADS_RIGHT_DS_WRITE_PROP
                    if ((accessrule.ActiveDirectoryRights & ActiveDirectoryRights.WriteProperty) == ActiveDirectoryRights.WriteProperty)
                    {
                        gotDelegation((SecurityIdentifier)accessrule.IdentityReference, "Write all prop");
                    }
                }
                else if ((accessrule.ObjectFlags & ObjectAceFlags.ObjectAceTypePresent) == ObjectAceFlags.ObjectAceTypePresent)
                {
                    // ADS_RIGHT_DS_CONTROL_ACCESS
                    if ((accessrule.ActiveDirectoryRights & ActiveDirectoryRights.ExtendedRight) == ActiveDirectoryRights.ExtendedRight)
                    {
                        foreach (KeyValuePair<Guid, string> extendedright in GuidsControlExtendedRights)
                        {
                            if (extendedright.Key == accessrule.ObjectType)
                            {
                                gotDelegation((SecurityIdentifier)accessrule.IdentityReference, extendedright.Value);
                            }
                        }
                    }
                    if (((accessrule.ActiveDirectoryRights & ActiveDirectoryRights.ExtendedRight) != 0 || ((int)accessrule.ActiveDirectoryRights & 4096) != 0) && accessrule.ObjectType == EnrollPermission)
                    {
                        // ADS_RIGHT_DS_SELF
                        if ((accessrule.ActiveDirectoryRights & ActiveDirectoryRights.Self) == ActiveDirectoryRights.Self)
                        {
                            foreach (KeyValuePair<Guid, string> validatewrite in GuidsControlValidatedWrites)
                            {
                                if (validatewrite.Key == accessrule.ObjectType)
                                {
                                    gotDelegation((SecurityIdentifier)accessrule.IdentityReference, validatewrite.Value);
                                }
                            }
                        }
                        // ADS_RIGHT_DS_WRITE_PROP
                        if ((accessrule.ActiveDirectoryRights & ActiveDirectoryRights.WriteProperty) == ActiveDirectoryRights.WriteProperty)
                        {
                            foreach (KeyValuePair<Guid, string> controlproperty in GuidsControlProperties)
                            {
                                if (controlproperty.Key == accessrule.ObjectType)
                                {
                                    gotDelegation((SecurityIdentifier)accessrule.IdentityReference, controlproperty.Value);
                                }
                            }
                            foreach (KeyValuePair<Guid, string> controlpropertyset in GuidsControlPropertiesSets)
                            {
                                if (controlpropertyset.Key == accessrule.ObjectType)
                                {
                                    gotDelegation((SecurityIdentifier)accessrule.IdentityReference, controlpropertyset.Value);
                                }
                            }
                        }
                        // ADS_RIGHT_DS_READ_PROP
                        if ((accessrule.ActiveDirectoryRights & ActiveDirectoryRights.ReadProperty) == ActiveDirectoryRights.ReadProperty)
                        {
                            foreach (KeyValuePair<Guid, string> controlproperty in ReadGuidsControlProperties)
                            {
                                if (controlproperty.Key == accessrule.ObjectType)
                                {
                                    gotDelegation((SecurityIdentifier)accessrule.IdentityReference, controlproperty.Value);
                                }
                            }
                        }
                    }
                }
                if (((accessrule.ActiveDirectoryRights & ActiveDirectoryRights.ExtendedRight) != 0 || ((int)accessrule.ActiveDirectoryRights & 4096) != 0) && accessrule.ObjectType == EnrollPermission)
                {
                    gotDelegation((SecurityIdentifier)accessrule.IdentityReference, "Enroll");
                }
            }
        }

        List<HealthcheckDelegationData> BuildDelegationList(ADWebService adws, Dictionary<string, string> sidCache, ADItem x)
        {
            var delegations = new List<HealthcheckDelegationData>();
            Dictionary<string, string> permissions = new Dictionary<string, string>();
            FilterDelegation(x,
                (SecurityIdentifier sid, string right)
                    =>
                {
                    if (!permissions.ContainsKey(sid.Value))
                    {
                        permissions[sid.Value] = right;
                    }
                    else
                    {
                        permissions[sid.Value] += ", " + right;
                    }
                }
            );
            foreach (string sid in permissions.Keys)
            {
                HealthcheckDelegationData delegation = new HealthcheckDelegationData();
                delegations.Add(delegation);
                delegation.DistinguishedName = x.DistinguishedName;
                delegation.SecurityIdentifier = sid;
                // avoid translation for anomaly detection later
                if (sid == "S-1-1-0")
                {
                    delegation.Account = GraphObjectReference.Everyone;
                }
                else if (sid == "S-1-5-7")
                {
                    delegation.Account = GraphObjectReference.Anonymous;
                }
                else if (sid == "S-1-5-11")
                {
                    delegation.Account = GraphObjectReference.AuthenticatedUsers;
                }
                else if (sid.EndsWith("-513"))
                {
                    delegation.Account = GraphObjectReference.DomainUsers;
                }
                else if (sid.EndsWith("-515"))
                {
                    delegation.Account = GraphObjectReference.DomainComputers;
                }
                else if (sid == "S-1-5-32-545")
                {
                    delegation.Account = GraphObjectReference.Users;
                }
                else
                {
                    if (!sidCache.ContainsKey(sid))
                    {
                        sidCache[sid] = adws.ConvertSIDToName(sid);
                    }
                    delegation.Account = sidCache[sid];
                }
                delegation.Right = permissions[sid];
            }
            return delegations;
        }

        [DebuggerDisplay("{DisplayName} {InternalName}")]
        private class GPO
        {
            public string InternalName { get; set; }
            public string DisplayName { get; set; }
            public bool IsDisabled { get; set; }
            public string DN { get; set; }

            public List<string> AppliedTo { get; set; }
            public List<int> AppliedOrder { get; set; }
        }

        private void GenerateGPOData(ADDomainInfo domainInfo, ADWebService adws)
        {
            healthcheckData.GPPPassword = new List<GPPPassword>();
            healthcheckData.GPPRightAssignment = new List<GPPRightAssignment>();
            healthcheckData.GPPLoginAllowedOrDeny = new List<GPPRightAssignment>();
            healthcheckData.GPPPasswordPolicy = new List<GPPSecurityPolicy>();
            healthcheckData.GPOLsaPolicy = new List<GPPSecurityPolicy>();
            healthcheckData.GPOScreenSaverPolicy = new List<GPPSecurityPolicy>();
            healthcheckData.TrustedCertificates = new List<HealthcheckCertificateData>();
            healthcheckData.GPOLoginScript = new List<HealthcheckGPOLoginScriptData>();
            healthcheckData.GPOLocalMembership = new List<GPOMembership>();
            healthcheckData.GPOEventForwarding = new List<GPOEventForwardingInfo>();
            healthcheckData.GPODelegation = new List<GPODelegationData>();
            healthcheckData.GPPFileDeployed = new List<GPPFileDeployed>();
            healthcheckData.GPPFirewallRules = new List<GPPFireWallRule>();
            healthcheckData.GPPTerminalServiceConfigs = new List<GPPTerminalServiceConfig>();
            healthcheckData.GPOAuditSimple = new List<GPOAuditSimpleData>();
            healthcheckData.GPOAuditAdvanced = new List<GPOAuditAdvancedData>();
            healthcheckData.GPOHardenedPath = new List<GPPHardenedPath>();
            healthcheckData.GPOWSUS = new List<HealthcheckWSUSData>();
            healthcheckData.GPOFolderOptions = new List<GPPFolderOption>();
            healthcheckData.GPODefenderASR = new List<HealthcheckDefenderASRData>();

            // subitility: GPOList = all active and not active GPO (but not the deleted ones)
            Dictionary<string, GPO> GPOList = new Dictionary<string, GPO>(StringComparer.OrdinalIgnoreCase);
            GetGPOList(domainInfo, adws, GPOList);
            SaveGPOListToHCData(GPOList);

            ParseGPOFiles(adws, domainInfo, GPOList);
            GenerateMsiData(domainInfo, adws, GPOList);
        }

        private void SaveGPOListToHCData(Dictionary<string, GPO> GPOList)
        {
            healthcheckData.GPOInfo = new List<GPOInfo>();
            foreach (var GPO in GPOList.Values)
            {
                healthcheckData.GPOInfo.Add(new GPOInfo()
                {
                    GPOId = GPO.InternalName,
                    GPOName = GPO.DisplayName,
                    IsDisabled = GPO.IsDisabled,
                    AppliedTo = GPO.AppliedTo,
                    AppliedOrder = GPO.AppliedOrder,
                });
            }
        }

        private void ParseGPOFiles(ADWebService adws, ADDomainInfo domainInfo, Dictionary<string, GPO> GPOList)
        {
            BlockingQueue<string> queue = new BlockingQueue<string>(200);
            int numberOfThread = 20;
            Thread[] threads = new Thread[numberOfThread];
            string uri = null;
            try
            {
                uri = "\\\\" + domainInfo.DnsHostName + "\\sysvol\\" + domainInfo.DomainName + "\\Policies";

                ParameterizedThreadStart threadFunction = (object input) =>
                {
                    adws.ThreadInitialization();
                    int ThreadId = (int)input;
                    for (; ; )
                    {
                        string directoryFullName = null;
                        if (!queue.Dequeue(out directoryFullName))
                        {
                            Trace.WriteLine("[" + ThreadId + "] stop");
                            break;
                        }
                        Trace.WriteLine("[" + ThreadId + "] working on " + directoryFullName);
                        string ADGPOName = adws.FileConnection.GetShortName(directoryFullName).ToLowerInvariant();
                        GPO gpo = null;
                        if (GPOList.ContainsKey(ADGPOName))
                        {
                            gpo = GPOList[ADGPOName];
                        }
                        ThreadGPOAnalysis(ThreadId, adws, directoryFullName, gpo, domainInfo);
                    }
                };

                // Consumers
                for (int i = 0; i < numberOfThread; i++)
                {
                    threads[i] = new Thread(threadFunction);
                    threads[i].Start(i);
                }

                adws.FileConnection.GetSubDirectories(uri);
                foreach (string fullDirectoryName in adws.FileConnection.GetSubDirectories(uri))
                {
                    queue.Enqueue(fullDirectoryName);
                }

                queue.Quit();
                Trace.WriteLine("examining file completed. Waiting for worker thread to complete");
                for (int i = 0; i < numberOfThread; i++)
                {
                    threads[i].Join();
                }
                Trace.WriteLine("Done insert file");
            }
            catch (UnauthorizedAccessException ex)
            {
                Trace.WriteLine("Exception while generating GPO Data: " + ex.Message);
                Trace.WriteLine(ex.StackTrace);
                lock (this)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Exception while generating GPO Data: " + ex.Message);
                    Console.ResetColor();
                }
            }
            catch (System.IO.IOException ex)
            {
                Trace.WriteLine("Exception while generating GPO Data: " + ex.Message);
                Trace.WriteLine(ex.StackTrace);
                lock (this)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Exception while generating GPO Data: " + ex.Message);
                    Console.ResetColor();
                }
            }
            catch (Exception ex)
            {
                Trace.WriteLine("Exception while generating GPO Data: " + ex.Message);
                Trace.WriteLine(ex.StackTrace);
                lock (this)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Exception while generating GPO Data: " + ex.Message);
                    Console.WriteLine(ex.StackTrace);
                    Console.ResetColor();
                }
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
        }

        private void GeneratePKIData(ADDomainInfo domainInfo, ADWebService adws)
        {
            // do it only on forest
            string test = domainInfo.ConfigurationNamingContext.Replace(domainInfo.DefaultNamingContext, "");
            if (!test.Contains("DC="))
            {
                bool PKIInstalled = false;
                WorkOnReturnedObjectByADWS callback =
                (ADItem x) =>
                {
                    PKIInstalled = true;
                };

                string[] properties = new string[] { "distinguishedName" };
                adws.Enumerate(domainInfo.ConfigurationNamingContext, "(distinguishedName=CN=Public Key Services,CN=Services," + domainInfo.ConfigurationNamingContext + ")", properties, callback);

                if (PKIInstalled)
                {
                    GenerateNTLMStoreData(domainInfo, adws);
                    GenerateCertificateTemplateData(domainInfo, adws);
                    GenerateADCSEnrollmentServerData(domainInfo, adws);
                }
            }
        }

        private Dictionary<string, List<string>> GetTemplateList(ADDomainInfo domainInfo, ADWebService adws)
        {
            string[] properties = new string[] {
                        "distinguishedName",
                        "certificateTemplates",
                        "name",
                        "dNSHostName",
                        };
            var output = new Dictionary<string, List<string>>();
            WorkOnReturnedObjectByADWS callback =
                (ADItem x) =>
                {
                    var caname = x.DNSHostName + "\\" + x.Name;
                    if (x.CertificateTemplates != null)
                    {
                        foreach (var ct in x.CertificateTemplates)
                        {
                            if (output.ContainsKey(ct))
                                output[ct].Add(caname);
                            else
                                output[ct] = new List<string>() { caname };
                        }
                    }
                };

            adws.Enumerate("CN=Public Key Services,CN=Services," + domainInfo.ConfigurationNamingContext, "(objectClass=pKIEnrollmentService)", properties, callback);
            return output;
        }

        private void GenerateCertificateTemplateData(ADDomainInfo domainInfo, ADWebService adws)
        {
            string[] properties = new string[] {
                        "distinguishedName",
                        "flags",
                        "msPKI-Cert-Template-OID",
                        "msPKI-Certificate-Name-Flag",
                        "msPKI-Enrollment-Flag",
                        "msPKI-Private-Key-Flag",
                        "msPKI-RA-Application-Policies",
                        "msPKI-Template-Schema-Version",
                        "name",
                        "pKIExtendedKeyUsage",
                        "nTSecurityDescriptor",
            };

            healthcheckData.CertificateTemplates = new List<HealthCheckCertificateTemplate>();
            var sidCache = new Dictionary<string, string>();
            var list = GetTemplateList(domainInfo, adws);

            // see CT_FLAG_ALLOW_ENROLL_ON_BEHALF_OF ?
            WorkOnReturnedObjectByADWS callback =
                (ADItem x) =>
                {
                    if (!list.ContainsKey(x.Name))
                        return;
                    HealthCheckCertificateTemplate ct = new HealthCheckCertificateTemplate();
                    healthcheckData.CertificateTemplates.Add(ct);

                    ct.Name = x.Name;
                    ct.CA = list[x.Name];
                    ct.Flags = x.Flags;
                    ct.OID = x.msPKICertTemplateOID;
                    ct.CAManagerApproval = (x.msPKIEnrollmentFlag & 2) != 0;
                    ct.NoSecurityExtension = (x.msPKIEnrollmentFlag & 0x80000) != 0;
                    if ((x.msPKICertificateNameFlag & 1) != 0)
                    {
                        ct.EnrolleeSupplies += 1;
                    }
                    if ((x.msPKICertificateNameFlag & 0x00010000) != 0)
                        ct.EnrolleeSupplies += 2;
                    if ((x.msPKICertificateNameFlag & 0x00000008) != 0)
                        ct.EnrolleeSupplies += 4;


                    ct.IssuanceRequirementsEmpty = true;
                    if (x.msPKITemplateSchemaVersion == 3 || (x.msPKITemplateSchemaVersion == 4 && (x.msPKIPrivateKeyFlag & 0x00000100) != 0))
                    {
                        if (!string.IsNullOrEmpty(x.msPKIRAApplicationPolicies))
                        {
                            // Syntax Option 2
                            var a = x.msPKIRAApplicationPolicies.Split('`');
                            for (int i = 0; i + 2 < a.Length; i += 3)
                            {
                                if (a[i] == "msPKI-RA-Application-Policies" && a[i + 1] == "PZPWSTR")
                                {
                                    if (!string.IsNullOrEmpty(a[i + 2]))
                                        ct.IssuanceRequirementsEmpty = false;
                                }
                            }
                        }
                    }
                    else
                    {
                        // Syntax Option 1
                        ct.IssuanceRequirementsEmpty = string.IsNullOrEmpty(x.msPKIRAApplicationPolicies);
                    }

                    if (x.NTSecurityDescriptor != null)
                    {
                        var delegations = BuildDelegationList(adws, sidCache, x);
                        ct.Delegations = delegations;

                        var account = MatchesBadUsersToCheck((SecurityIdentifier)x.NTSecurityDescriptor.GetOwner(typeof(SecurityIdentifier)));
                        if (account != null)
                        {
                            ct.VulnerableTemplateACL = true;
                        }
                        else
                        {
                            // see https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/211ab1e3-bad6-416d-9d56-8480b42617a4

                            // look for explicit autorization granted to the user who created the object
                            foreach (ActiveDirectoryAccessRule accessrule in x.NTSecurityDescriptor.GetAccessRules(true, false, typeof(SecurityIdentifier)))
                            {
                                if (accessrule.AccessControlType == AccessControlType.Deny)
                                    continue;
                                account = MatchesBadUsersToCheck((SecurityIdentifier)accessrule.IdentityReference);
                                if (account == null)
                                {
                                    continue;
                                }
                                if ((accessrule.ActiveDirectoryRights & ActiveDirectoryRights.WriteDacl) == ActiveDirectoryRights.WriteDacl ||
                                    (accessrule.ActiveDirectoryRights & ActiveDirectoryRights.WriteOwner) == ActiveDirectoryRights.WriteOwner ||
                                    (accessrule.ActiveDirectoryRights & ActiveDirectoryRights.GenericWrite) == ActiveDirectoryRights.GenericWrite)
                                {
                                    ct.VulnerableTemplateACL = true;
                                }
                                // all extended rights
                                if (((accessrule.ActiveDirectoryRights & ActiveDirectoryRights.ExtendedRight) != 0 || ((int)accessrule.ActiveDirectoryRights & 4096) != 0) && accessrule.ObjectType == EnrollPermission)
                                {
                                    ct.LowPrivCanEnroll = true;
                                }
                            }
                        }

                    }
                    var EKU = new List<string>();
                    if (x.pKIExtendedKeyUsage != null)
                        EKU.AddRange(x.pKIExtendedKeyUsage);
                    // client authentification then smart card logon then PKINIT Client Authentication then any purpose
                    ct.HasAuthenticationEku = EKU.Count == 0 || EKU.Contains("1.3.6.1.5.5.7.3.2") || EKU.Contains("1.3.6.1.4.1.311.20.2.2") || EKU.Contains("1.3.6.1.5.2.3.4") || EKU.Contains("2.5.29.37.0");
                    ct.HasAnyPurpose = EKU.Count == 0 || EKU.Contains("2.5.29.37.0");
                    ct.EnrollmentAgentTemplate = EKU.Contains("1.3.6.1.4.1.311.20.2.1");
                };

            adws.Enumerate("CN=Public Key Services,CN=Services," + domainInfo.ConfigurationNamingContext, "(objectClass=pKICertificateTemplate)", properties, callback);
        }

        private void GenerateNTLMStoreData(ADDomainInfo domainInfo, ADWebService adws)
        {
            string[] properties = new string[] {
                        "distinguishedName",
                        "cACertificate",
            };
            WorkOnReturnedObjectByADWS callback =
                (ADItem x) =>
                {
                    if (x.CACertificate != null)
                    {
                        foreach (X509Certificate2 certificate in x.CACertificate)
                        {
                            HealthcheckCertificateData data = new HealthcheckCertificateData();
                            data.Source = "NTLMStore";
                            data.Store = "NTLMStore";
                            data.Certificate = certificate.GetRawCertData();
                            healthcheckData.TrustedCertificates.Add(data);
                        }
                    }
                };


            adws.Enumerate(domainInfo.ConfigurationNamingContext, "(distinguishedName=CN=NTAuthCertificates,CN=Public Key Services,CN=Services," + domainInfo.ConfigurationNamingContext + ")", properties, callback);

        }

        private void GenerateADCSEnrollmentServerData(ADDomainInfo domainInfo, ADWebService adws)
        {

            healthcheckData.CertificateEnrollments = new List<HealthCheckCertificateEnrollment>();

            string[] properties = new string[] {
                        "dNSHostName",
                        "name"
            };
            List<ADItem> results = new List<ADItem>();
            WorkOnReturnedObjectByADWS callback =
                (ADItem x) =>
                {
                    if (!string.IsNullOrEmpty(x.DNSHostName))
                    {
                        results.Add(x);
                    }
                };


            adws.Enumerate("CN=Public Key Services,CN=Services," + domainInfo.ConfigurationNamingContext, "(objectClass=pKIEnrollmentService)", properties, callback);


            BlockingQueue<ADItem> queue = new BlockingQueue<ADItem>(200);
            int numberOfThread = 20;
            Thread[] threads = new Thread[numberOfThread];
            ParameterizedThreadStart threadFunction = (object input) =>
            {
                int ThreadId = (int)input;
                for (; ; )
                {
                    ADItem x = null;
                    if (!queue.Dequeue(out x))
                    {
                        Trace.WriteLine("[" + ThreadId + "] stop");
                        break;
                    }
                    Trace.WriteLine("[" + ThreadId + "] working on " + x.DNSHostName + " - " + x.Name);
                    GenerateADCSEnrollmentServerTests(adws, x.DNSHostName, x.Name);
                }
            };

            // Consumers
            for (int i = 0; i < numberOfThread; i++)
            {
                threads[i] = new Thread(threadFunction);
                threads[i].Start(i);
            }

            foreach (var x in results)
            {
                queue.Enqueue(x);
            }

            queue.Quit();
            Trace.WriteLine("adcs test completed. Waiting for worker thread to complete");
            for (int i = 0; i < numberOfThread; i++)
            {
                threads[i].Join();
            }
            Trace.WriteLine("Done adcs test");
        }

        private void GenerateADCSEnrollmentServerTests(ADWebService adws, string dnsHostName, string CAName)
        {
            var enrollmentServer = new HealthCheckCertificateEnrollment();
            enrollmentServer.Name = dnsHostName;
            healthcheckData.CertificateEnrollments.Add(enrollmentServer);

            var uri = new Uri("https://" + dnsHostName + "/certsrv/certrqxt.asp");

            byte[] certificate;
            var protocols = new List<string>();
            Trace.WriteLine("[" + DateTime.Now + "] Test for " + dnsHostName + " 1 starts");
            GenerateTLSInfo(uri.Host, uri.Port, protocols, out certificate, "[" + DateTime.Now + "] ");
            Trace.WriteLine("[" + DateTime.Now + "] Test for " + dnsHostName + " 2 done for TLS");

            enrollmentServer.SSLProtocol = protocols;

            if (DoesComputerMatchDns(dnsHostName))
            {
                Trace.WriteLine("Test ignored because tested on the server itself");
                return;
            }
            // web enrollment
            // https access
            // channel binding
            var result = ConnectionTester.TestExtendedAuthentication(uri, adws.Credential, "[" + DateTime.Now + "] Test for " + dnsHostName + " ");
            Trace.WriteLine("[" + DateTime.Now + "] Test for " + dnsHostName + " 3 done for TestExtendedAuthentication");
            if (result == ConnectionTesterStatus.ChannelBindingDisabled)
            {
                enrollmentServer.WebEnrollmentChannelBindingDisabled = true;
                enrollmentServer.WebEnrollmentHttps = true;
            }
            else if (result == ConnectionTesterStatus.ChannelBindingEnabled)
            {
                enrollmentServer.WebEnrollmentHttps = true;
            }
            // http access
            uri = new Uri("http://" + dnsHostName + "/certsrv/certrqxt.asp");
            result = ConnectionTester.TestConnection(uri, adws.Credential, "[" + DateTime.Now + "] Test for " + dnsHostName + " ");
            Trace.WriteLine("[" + DateTime.Now + "] Test for " + dnsHostName + " 4 done for TestConnection");
            if (result == ConnectionTesterStatus.AuthenticationSuccessfull)
            {
                enrollmentServer.WebEnrollmentHttp = true;

            }
            // CES
            // https access
            // channel binding
            uri = new Uri("https://" + dnsHostName + "/" + System.Net.WebUtility.UrlEncode(CAName) + "_CES_Kerberos/service.svc");

            result = ConnectionTester.TestExtendedAuthentication(uri, adws.Credential, "[" + DateTime.Now + "] Test for " + dnsHostName + " ");
            Trace.WriteLine("[" + DateTime.Now + "] Test for " + dnsHostName + " 5 done for TestExtendedAuthentication");
            if (result == ConnectionTesterStatus.ChannelBindingDisabled)
            {
                enrollmentServer.CESHttps = true;
                enrollmentServer.CESChannelBindingDisabled = true;
            }
            else if (result == ConnectionTesterStatus.ChannelBindingEnabled)
            {
                enrollmentServer.CESHttps = true;
            }

            // http access
            uri = new Uri("http://" + dnsHostName + "/" + System.Net.WebUtility.UrlEncode(CAName) + "_CES_Kerberos/service.svc");
            result = ConnectionTester.TestConnection(uri, adws.Credential, "[" + DateTime.Now + "] Test for " + dnsHostName + " ");
            Trace.WriteLine("[" + DateTime.Now + "] Test for " + dnsHostName + " 6 done for TestConnection");
            if (result == ConnectionTesterStatus.AuthenticationSuccessfull)
            {
                enrollmentServer.CESHttp = true;

            }
        }

        void GenerateSCCMData(ADDomainInfo domainInfo, ADWebService adws)
        {
            string[] propertiesSchema = new string[] {
                        "distinguishedName",
                        "whenCreated",
            };

            adws.Enumerate(domainInfo.SchemaNamingContext, "(name=MS-SMS-MP-Name)", propertiesSchema,
                (ADItem aditem) =>
                {
                    healthcheckData.SCCMInstalled = aditem.WhenCreated;
                }
                , "OneLevel");

            if (healthcheckData.SCCMInstalled == DateTime.MinValue)
            {
                return;
            }

            healthcheckData.SCCMServers = new List<HealthCheckSCCMServer>();

            string[] properties = new string[] {
                        "distinguishedName",
                        "mSSMSCapabilities",
                        "mSSMSMPName",
                        "mSSMSVersion",
            };
            WorkOnReturnedObjectByADWS callback =
                (ADItem x) =>
                {
                    var sccm = new HealthCheckSCCMServer();
                    sccm.Name = x.DistinguishedName;
                    sccm.Capabilities = x.mSSMSCapabilities;
                    sccm.MPName = x.mSSMSMPName;
                    sccm.Version = x.mSSMSVersion;
                    healthcheckData.SCCMServers.Add(sccm);
                };
            adws.Enumerate("CN=System Management,CN=System," + domainInfo.DefaultNamingContext, "(objectClass=mSSMSManagementPoint)", properties, callback);
        }


        private void GenerateExchangeInfo(ADDomainInfo domainInfo, ADWebService adws)
        {

            adws.Enumerate(domainInfo.SchemaNamingContext,
                                       "(cn=ms-Exch-Schema-Version-Pt)",
                                        new string[] { "rangeUpper", "whenCreated" }, (ADItem aditem) =>
                                        {
                                            healthcheckData.ExchangeInstall = aditem.WhenCreated;
                                            healthcheckData.ExchangeSchemaVersion = aditem.RangeUpper;
                                        });


            healthcheckData.ExchangeServers = new List<HealthcheckExchangeServer>();
            if (healthcheckData.ExchangeSchemaVersion > 0)
            {
                adws.Enumerate(domainInfo.ConfigurationNamingContext,
                                           "(objectCategory=msExchExchangeServer)",
                                            new string[] { "distinguishedName", "msExchCurrentServerRoles", "msExchComponentStates", "msExchInternetWebProxy", "serialNumber", "whenCreated", "whenChanged", "name" },
                                            (ADItem aditem) =>
                                            {
                                                healthcheckData.ExchangeInstall = aditem.WhenCreated;
                                                healthcheckData.ExchangeServers.Add(new HealthcheckExchangeServer
                                                {
                                                    Name = aditem.Name,
                                                    CreationDate = aditem.WhenCreated,
                                                    ChangedDate = aditem.WhenChanged,
                                                    ServerRoles = aditem.msExchCurrentServerRoles,
                                                    ComponentStates = aditem.msExchComponentStates,
                                                    InternetWebProxy = aditem.msExchInternetWebProxy,
                                                    SerialNumber = aditem.serialNumber,
                                                });
                                            });
            }
        }


        private void GenerateMsiData(ADDomainInfo domainInfo, ADWebService adws, Dictionary<string, GPO> GPOList)
        {
            // see https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsi/92188849-64c8-45dc-8c0c-9cc0ee40e03b
            string[] properties = new string[] {
                        "distinguishedName",
                        "msiFileList",
            };
            WorkOnReturnedObjectByADWS callback =
                (ADItem x) =>
                {
                    if (x.msiFileList == null)
                        return;
                    int pos1 = x.DistinguishedName.IndexOf('{');
                    if (pos1 < 0)
                        return;
                    int pos2 = x.DistinguishedName.IndexOf('}', pos1);
                    string GPOGuid = x.DistinguishedName.Substring(pos1, pos2 - pos1 + 1).ToLowerInvariant();
                    if (!GPOList.ContainsKey(GPOGuid))
                        return;
                    var GPO = GPOList[GPOGuid];
                    if (GPO.IsDisabled)
                        return;
                    string section = (x.DistinguishedName.Contains("Machine") ? "Computer" : "User");
                    foreach (var msiFileItem in x.msiFileList)
                    {
                        var msiFile = msiFileItem.Split(':');
                        if (msiFile.Length < 2)
                            continue;
                        var file = new GPPFileDeployed();
                        file.GPOName = GPO.DisplayName;
                        file.GPOId = GPO.InternalName;
                        file.Type = "Application (" + section + " section)";
                        file.FileName = msiFile[1];
                        file.Delegation = new List<HealthcheckScriptDelegationData>();
                        Trace.WriteLine("before check msi: " + file.FileName);
                        lock (healthcheckData.GPPFileDeployed)
                        {
                            healthcheckData.GPPFileDeployed.Add(file);
                        }
                        if (adws.FileConnection.FileExists(file.FileName))
                        {
                            try
                            {
                                var ac = adws.FileConnection.GetFileSecurity(file.FileName);
                                foreach (var value in AnalyzeFileSystemSecurity(ac, true))
                                {
                                    file.Delegation.Add(new HealthcheckScriptDelegationData()
                                    {
                                        Account = value.Value,
                                        Right = value.Key,
                                    }
                                    );
                                }
                            }
                            catch (Exception ex)
                            {
                                Trace.WriteLine("Unable to analyze " + file.FileName + " " + ex.Message);
                            }
                        }
                        Trace.WriteLine("after check msi: " + file.FileName);
                    }

                };
            adws.Enumerate(domainInfo.DefaultNamingContext, "(objectClass=packageRegistration)", properties, callback);
        }

        void ThreadGPOAnalysis(int ThreadId, ADWebService adws, string directoryFullName, GPO GPO, ADDomainInfo domainInfo)
        {
            string step = "initial";
            string shortName = adws.FileConnection.GetShortName(directoryFullName);
            try
            {
                string path;
                // work on all GPO including disabled ones
                step = "extract GPP passwords";
                foreach (string target in new string[] { "user", "machine" })
                {
                    foreach (string shortname in new string[] {
                        "groups.xml","services.xml","scheduledtasks.xml",
                        "datasources.xml","printers.xml","drives.xml",
                    })
                    {
                        path = directoryFullName + @"\" + target + @"\Preferences\" + shortname.Replace(".xml", "") + "\\" + shortname;
                        if (adws.FileConnection.FileExists(path))
                        {
                            ExtractGPPPassword(adws, shortname, path, GPO, "Unknown [" + shortName + "]");
                        }
                    }
                }
                path = directoryFullName + @"\Machine\Preferences\Registry\Registry.xml";
                if (adws.FileConnection.FileExists(path))
                {
                    ExtractLoginPassword(adws, path, GPO, "Unknown [" + shortName + "]");
                }
                // work only on active GPO
                if (GPO == null || GPO.IsDisabled)
                    return;
                path = directoryFullName + @"\Machine\Preferences\Groups\Groups.xml";
                if (adws.FileConnection.FileExists(path))
                {
                    step = "extract GPP local group assignment";
                    ExtractLocalGroupAssignment(adws, path, GPO);
                }
                path = directoryFullName + @"\Machine\Microsoft\Windows nt\SecEdit\GptTmpl.inf";
                if (adws.FileConnection.FileExists(path))
                {
                    step = "extract GPP privileges";
                    ExtractGPPPrivilegePasswordLsaSettingEtc(adws, path, GPO, domainInfo);
                }
                path = directoryFullName + @"\MACHINE\Microsoft\Windows NT\Audit\audit.csv";
                if (adws.FileConnection.FileExists(path))
                {
                    step = "extract audit";
                    ExtractGPOAudit(adws, path, GPO, domainInfo);
                }
                step = "extract GPO login script";
                ExtractGPOLoginScript(adws, domainInfo, directoryFullName, GPO);
                path = directoryFullName + @"\User\Preferences\Files\Files.xml";
                if (adws.FileConnection.FileExists(path))
                {
                    step = "extract Files info";
                    ExtractGPPFile(adws, path, GPO, domainInfo, "User");
                }
                path = directoryFullName + @"\Machine\Preferences\Files\Files.xml";
                if (adws.FileConnection.FileExists(path))
                {
                    step = "extract Files info";
                    ExtractGPPFile(adws, path, GPO, domainInfo, "Computer");
                }
                try
                {
                    step = "extract Registry Pol info";
                    ExtractRegistryPolInfo(adws, domainInfo, directoryFullName, GPO);
                }
                catch (Exception ex)
                {
                    Trace.WriteLine("GPO Pol info failed " + shortName + " " + GPO.DisplayName);
                    Trace.WriteLine("Exception " + ex.Message);
                    Trace.WriteLine(ex.StackTrace);
                }
                step = "check GPO permissions";
                ExtractGPODelegation(adws, directoryFullName, GPO);
                step = "check GPO settings";
                path = directoryFullName + @"\Machine\Preferences\Registry\Registry.xml";
                if (adws.FileConnection.FileExists(path))
                {
                    ExtractNetSessionHardeningFromRegistryXml(path, GPO);
                }
                step = "check Folder option";
                path = directoryFullName + @"\MACHINE\Preferences\FolderOptions\FolderOptions.xml";
                if (adws.FileConnection.FileExists(path))
                {
                    ExtractFolderOptions(adws, path, GPO);
                }

            }
            catch (UnauthorizedAccessException ex)
            {
                lock (this)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Unable to analyze the GPO: " + shortName + "(" + ex.Message + ")");
                    Trace.WriteLine("[" + ThreadId + "] Unable to analyze the GPO: " + shortName + "(" + ex.Message + ")");
                    Console.ResetColor();
                }
            }
            catch (Exception ex)
            {
                lock (this)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Unable to analyze the GPO: " + shortName + "(" + ex.Message + ")");
                    Trace.WriteLine("[" + ThreadId + "] Unable to analyze the GPO: " + shortName + "(" + ex.Message + ")");
                    Console.WriteLine("More details are available in the trace log (step: " + step + ")");
                    Trace.WriteLine(ex.StackTrace);
                    Console.ResetColor();
                }
            }
        }

        private void ExtractLocalGroupAssignment(ADWebService adws, string path, GPO GPO)
        {
            XmlDocument doc = new XmlDocument();
            doc.Load(path);
            XmlNodeList nodeList = doc.SelectNodes(@"//Group");
            foreach (XmlNode node in nodeList)
            {
                XmlNode actionNode = node.SelectSingleNode(@"Properties/@action");
                if (actionNode != null)
                {
                    switch (actionNode.Value.ToUpperInvariant())
                    {
                        case "C":
                        case "U":
                        case "R":
                            break;
                        default:
                            continue;
                    }
                }
                var groupNameNode = node.SelectSingleNode("@name");
                if (groupNameNode == null)
                    continue;
                foreach (XmlNode userNameNode in node.SelectNodes(@"Properties/Members/Member[@action=""ADD""]"))
                {
                    var sidnode = userNameNode.SelectSingleNode("@sid");
                    if (sidnode == null)
                        continue;
                    string sid = sidnode.Value;

                    var userNode = userNameNode.SelectSingleNode("@name");
                    string user = null;
                    if (userNode != null)
                        user = userNode.Value;

                    if (sid == "S-1-1-0")
                    {
                        user = GraphObjectReference.Everyone;
                    }
                    else if (sid == "S-1-5-7")
                    {
                        user = GraphObjectReference.Anonymous;
                    }
                    else if (sid == "S-1-5-11")
                    {
                        user = GraphObjectReference.AuthenticatedUsers;
                    }
                    else if (sid == "S-1-5-32-545")
                    {
                        user = GraphObjectReference.Users;
                    }
                    else if (sid.EndsWith("-513"))
                    {
                        user = GraphObjectReference.DomainUsers;
                    }
                    else if (sid.EndsWith("-515"))
                    {
                        user = GraphObjectReference.DomainComputers;
                    }
                    else if (sid.StartsWith("S-1", StringComparison.InvariantCultureIgnoreCase))
                    {
                        if (user == null)
                            user = adws.ConvertSIDToName(sid.Substring(1));
                    }
                    GPOMembership membership = new GPOMembership();
                    membership.GPOName = GPO.DisplayName;
                    membership.GPOId = GPO.InternalName;
                    membership.User = user;
                    membership.MemberOf = groupNameNode.Value;

                    lock (healthcheckData.GPOLocalMembership)
                    {
                        healthcheckData.GPOLocalMembership.Add(membership);
                    }
                }
            }
        }

        private void ExtractLoginPassword(IADConnection adws, string path, GPO GPO, string alternateNameIfGPODoesNotExists)
        {
            XmlDocument doc = new XmlDocument();
            doc.Load(path);
            XmlNodeList nodeList = doc.SelectNodes(@"//Registry[@name=""DefaultPassword""]");
            foreach (XmlNode node in nodeList)
            {
                XmlNode password = node.SelectSingleNode("Properties/@value");
                // no password
                if (password == null)
                    continue;
                // password has been manually changed
                if (String.IsNullOrEmpty(password.Value))
                    continue;
                GPPPassword PasswordData = new GPPPassword();
                PasswordData.GPOName = (GPO == null ? alternateNameIfGPODoesNotExists : GPO.DisplayName);
                PasswordData.GPOId = (GPO == null ? null : GPO.InternalName);
                PasswordData.Password = password.Value;

                XmlNode userNameNode = node.SelectSingleNode(@"//Registry[@name=""DefaultUserName""]/Properties/@value");
                PasswordData.UserName = (userNameNode != null ? userNameNode.Value : string.Empty);

                XmlNode changed = node.SelectSingleNode("@changed");
                if (changed != null)
                {
                    PasswordData.Changed = DateTime.Parse(changed.Value);
                }
                else
                {
                    PasswordData.Changed = adws.FileConnection.GetLastWriteTime(path);
                }
                PasswordData.Type = "registry.xml";
                PasswordData.Other = "Autologon info";
                lock (healthcheckData.GPPPassword)
                {
                    healthcheckData.GPPPassword.Add(PasswordData);
                }
            }
        }

        private void ExtractNetSessionHardeningFromRegistryXml(string path, GPO gpo)
        {
            const string valueName = "SrvsvcSessionInfo";
            const string valuePath = @"SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity";

            var xPath = string.Format("//Registry/Properties[translate(@name, \"{0}\", \"{1}\")=\"{2}\"][translate(@key, \"{0}\", \"{1}\")=\"{3}\"]",
                                      LatinUpperCase,
                                      LatinLowerCase,
                                      valueName.ToLowerInvariant(),
                                      valuePath.ToLowerInvariant());

            var doc = new XmlDocument();
            doc.Load(path);

            var nodeList = doc.SelectNodes(xPath);
            if (nodeList.Count == 0)
            {
                return;
            }

            GPPSecurityPolicy secPol = null;
            foreach (var policy in healthcheckData.GPOLsaPolicy)
            {
                if (policy.GPOId == gpo.InternalName)
                {
                    secPol = policy;
                    break;
                }
            }

            if (secPol == null)
            {
                secPol = new GPPSecurityPolicy
                {
                    GPOName = gpo.DisplayName,
                    GPOId = gpo.InternalName
                };

                lock (healthcheckData.GPOLsaPolicy)
                {
                    healthcheckData.GPOLsaPolicy.Add(secPol);
                }

                secPol.Properties = new List<GPPSecurityPolicyProperty>();
            }

            secPol.Properties.Add(new GPPSecurityPolicyProperty(valueName, 1));
        }

        private void ExtractFolderOptions(ADWebService adws, string path, GPO gpo)
        {
            var doc = new XmlDocument();
            doc.Load(path);

            var nodeList = doc.SelectNodes("//FolderOptions/FileType");
            if (nodeList.Count == 0)
            {
                return;
            }
            foreach (XmlNode node in nodeList)
            {
                XmlNode action = node.SelectSingleNode("Properties/@action");
                XmlNode fileExt = node.SelectSingleNode("Properties/@fileExt");
                XmlNode openAction = node.SelectSingleNode("Properties/Actions/Action[@name=\"open\"]");
                if (openAction != null)
                {
                    XmlNode appUsed = openAction.SelectSingleNode("@appUsed");

                    var folderOption = new GPPFolderOption
                    {
                        GPOName = gpo.DisplayName,
                        GPOId = gpo.InternalName,
                        Action = action.Value,
                        FileExt = fileExt.Value,
                        OpenApp = appUsed.Value,
                    };

                    lock (healthcheckData.GPOFolderOptions)
                    {
                        healthcheckData.GPOFolderOptions.Add(folderOption);
                    }
                }
            }

        }

        private void ExtractRegistryPolInfo(IADConnection adws, ADDomainInfo domainInfo, string directoryFullName, GPO GPO)
        {
            GPPSecurityPolicy PSO = null;
            foreach (string gpotarget in new string[] { "Machine", "User" })
            {
                string path = directoryFullName + "\\" + gpotarget + "\\registry.pol";
                if (adws.FileConnection.FileExists(path))
                {
                    RegistryPolReader reader = new RegistryPolReader(adws.FileConnection);
                    reader.LoadFile(path);
                    if (gpotarget == "Machine")
                    {
                        ExtractFirewallRules(GPO, reader);
                        ExtractScreenSavePolicy(GPO, ref PSO, reader);
                        ExtractEnableMulticast(GPO, reader);
                        ExtractKerberosSettings(GPO, reader);
                        ExtractPowershellLogging(GPO, reader);
                        ExtractHardeningPath(GPO, reader);

                        ExtractTerminalServerConfig(GPO, reader);

                        ProcessWSUSData(reader, GPO);
                        ProcessDefenderASRData(reader, GPO);
                        ExtractEvenForwardingInfo(GPO, reader);
                    }
                    else
                    {
                        ExtractScreenSavePolicyUserSide(GPO, ref PSO, reader);
                    }
                    ExtractTrustedCertificates(GPO, gpotarget, reader);
                    ExtractLogonScripts(adws, domainInfo, GPO, gpotarget, reader);
                }
            }
        }

        private void ExtractTerminalServerConfig(GPO GPO, RegistryPolReader reader)
        {
            int intvalue;
            GPPTerminalServiceConfig config = null;
            // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsts/d7cb8c2d-f60e-42d6-b8f4-e617ad4d8c1b
            if (reader.IsValueSet(@"Software\Policies\Microsoft\Windows NT\Terminal Services", "MaxIdleTime", out intvalue))
            {
                if (config == null)
                {
                    config = new GPPTerminalServiceConfig();
                    config.GPOName = GPO.DisplayName;
                    config.GPOId = GPO.InternalName;
                    lock (healthcheckData.GPOScreenSaverPolicy)
                    {
                        healthcheckData.GPPTerminalServiceConfigs.Add(config);
                    }
                }
                config.MaxIdleTime = intvalue;
            }
            if (reader.IsValueSet(@"Software\Policies\Microsoft\Windows NT\Terminal Services", "MaxDisconnectionTime", out intvalue))
            {
                if (config == null)
                {
                    config = new GPPTerminalServiceConfig();
                    config.GPOName = GPO.DisplayName;
                    config.GPOId = GPO.InternalName;
                    lock (healthcheckData.GPOScreenSaverPolicy)
                    {
                        healthcheckData.GPPTerminalServiceConfigs.Add(config);
                    }
                }
                config.MaxDisconnectionTime = intvalue;
            }
            if (reader.IsValueSet(@"Software\Policies\Microsoft\Windows NT\Terminal Services", "fDisableCpm", out intvalue))
            {
                if (config == null)
                {
                    config = new GPPTerminalServiceConfig();
                    config.GPOName = GPO.DisplayName;
                    config.GPOId = GPO.InternalName;
                    lock (healthcheckData.GPOScreenSaverPolicy)
                    {
                        healthcheckData.GPPTerminalServiceConfigs.Add(config);
                    }
                }
                config.fDisableCpm = intvalue > 0;
            }

        }

        private void ExtractLogonScripts(IADConnection adws, ADDomainInfo domainInfo, GPO GPO, string gpotarget, RegistryPolReader reader)
        {
            foreach (RegistryPolRecord record in reader.SearchRecord(@"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"))
            {
                if (record.Value == "**delvals.")
                    continue;
                string filename = Encoding.Unicode.GetString(record.ByteValue).Trim();
                if (string.IsNullOrEmpty(filename))
                    continue;
                filename = filename.Replace("\0", string.Empty);
                HealthcheckGPOLoginScriptData loginscript = new HealthcheckGPOLoginScriptData();
                loginscript.GPOName = GPO.DisplayName;
                loginscript.GPOId = GPO.InternalName;
                loginscript.Action = "Logon";
                // this is bad, I'm assuming that the file name doesn't contain any space which is wrong.
                // but a real command line parsing will bring more anomalies.
                var filePart = NativeMethods.SplitArguments(filename);
                loginscript.Source = "Registry.pol (" + (gpotarget == "Machine" ? "Computer" : "User") + " section)";
                loginscript.CommandLine = filePart[0];
                if (loginscript.CommandLine.StartsWith("\\\\"))
                {
                    loginscript.Delegation = CheckScriptPermission(adws, domainInfo, loginscript.CommandLine);
                }
                if (filePart.Length > 1)
                {
                    for (int i = 1; i < filePart.Length; i++)
                    {
                        if (i > 1)
                            loginscript.Parameters += " ";
                        loginscript.Parameters += filePart[i];
                    }
                }
                lock (healthcheckData.GPOLoginScript)
                {
                    healthcheckData.GPOLoginScript.Add(loginscript);
                }
            }
        }

        private void ExtractTrustedCertificates(GPO GPO, string gpotarget, RegistryPolReader reader)
        {
            // search for certificates
            foreach (string storename in new string[] { "Root", "CA", "Trust", "TrustedPeople", "TrustedPublisher", })
            {
                X509Certificate2Collection store = null;
                if (reader.HasCertificateStore(storename, out store))
                {
                    foreach (X509Certificate2 certificate in store)
                    {
                        HealthcheckCertificateData data = new HealthcheckCertificateData();
                        data.Source = "GPO:" + GPO.DisplayName + ";" + gpotarget;
                        data.Store = storename;
                        data.Certificate = certificate.GetRawCertData();
                        lock (healthcheckData.TrustedCertificates)
                        {
                            healthcheckData.TrustedCertificates.Add(data);
                        }
                    }
                }
            }
        }

        private void ExtractScreenSavePolicyUserSide(GPO GPO, ref GPPSecurityPolicy PSO, RegistryPolReader reader)
        {
            int intvalue;
            //https://msdn.microsoft.com/fr-fr/library/cc781591(v=ws.10).aspx
            if (reader.IsValueSetIntAsStringValue(@"software\policies\microsoft\windows\Control Panel\Desktop", "ScreenSaveTimeOut", out intvalue))
            {
                if (PSO == null)
                {
                    PSO = new GPPSecurityPolicy();
                    PSO.GPOName = GPO.DisplayName;
                    PSO.GPOId = GPO.InternalName;
                    lock (healthcheckData.GPOScreenSaverPolicy)
                    {
                        healthcheckData.GPOScreenSaverPolicy.Add(PSO);
                    }
                    PSO.Properties = new List<GPPSecurityPolicyProperty>();
                }
                PSO.Properties.Add(new GPPSecurityPolicyProperty("ScreenSaveTimeOut", intvalue));
            }
            //https://msdn.microsoft.com/fr-fr/library/cc787364(v=ws.10).aspx
            if (reader.IsValueSetIntAsStringValue(@"software\policies\microsoft\windows\Control Panel\Desktop", "ScreenSaveActive", out intvalue))
            {
                if (PSO == null)
                {
                    PSO = new GPPSecurityPolicy();
                    PSO.GPOName = GPO.DisplayName;
                    PSO.GPOId = GPO.InternalName;
                    lock (healthcheckData.GPOScreenSaverPolicy)
                    {
                        healthcheckData.GPOScreenSaverPolicy.Add(PSO);
                    }
                    PSO.Properties = new List<GPPSecurityPolicyProperty>();
                }
                PSO.Properties.Add(new GPPSecurityPolicyProperty("ScreenSaveActive", intvalue));
            }
            // https://technet.microsoft.com/en-us/library/cc959646.aspx
            if (reader.IsValueSetIntAsStringValue(@"software\policies\microsoft\windows\Control Panel\Desktop", "ScreenSaverIsSecure", out intvalue))
            {
                if (PSO == null)
                {
                    PSO = new GPPSecurityPolicy();
                    PSO.GPOName = GPO.DisplayName;
                    PSO.GPOId = GPO.InternalName;
                    lock (healthcheckData.GPOScreenSaverPolicy)
                    {
                        healthcheckData.GPOScreenSaverPolicy.Add(PSO);
                    }
                    PSO.Properties = new List<GPPSecurityPolicyProperty>();
                }
                PSO.Properties.Add(new GPPSecurityPolicyProperty("ScreenSaverIsSecure", intvalue));
            }
        }

        private void ExtractEvenForwardingInfo(GPO GPO, RegistryPolReader reader)
        {
            for (int i = 1; ; i++)
            {
                string server = null;
                if (reader.IsValueSet(@"Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager", i.ToString(), out server))
                {
                    lock (healthcheckData.GPOEventForwarding)
                    {
                        GPOEventForwardingInfo info = new GPOEventForwardingInfo();
                        info.GPOName = GPO.DisplayName;
                        info.GPOId = GPO.InternalName;
                        info.Order = i;
                        info.Server = server;
                        healthcheckData.GPOEventForwarding.Add(info);
                    }
                }
                else
                {
                    break;
                }
            }
        }

        private void ExtractHardeningPath(GPO GPO, RegistryPolReader reader)
        {
            var HardenedPaths = reader.SearchRecord(@"Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths");
            if (HardenedPaths.Count > 0)
            {
                foreach (var record in HardenedPaths)
                {
                    if (string.IsNullOrEmpty(record.Key))
                        continue;
                    if (record.Type != Microsoft.Win32.RegistryValueKind.String)
                        continue;
                    var stringvalue = UnicodeEncoding.Unicode.GetString(record.ByteValue).TrimEnd('\0');
                    if (string.IsNullOrEmpty(stringvalue))
                        continue;
                    var hardenedPath = new GPPHardenedPath();
                    hardenedPath.Key = record.Value;
                    hardenedPath.GPOName = GPO.DisplayName;
                    hardenedPath.GPOId = GPO.InternalName;
                    foreach (var v in stringvalue.Split(','))
                    {
                        if (string.IsNullOrEmpty(v))
                            continue;
                        var w = v.Split('=');
                        if (w.Length < 2)
                            continue;
                        switch (w[0].ToLowerInvariant().Trim())
                        {
                            case "requiremutualauthentication":
                                hardenedPath.RequireMutualAuthentication = int.Parse(w[1]) == 1;
                                break;
                            case "requireprivacy":
                                hardenedPath.RequirePrivacy = int.Parse(w[1]) == 1;
                                break;
                            case "requireintegrity":
                                hardenedPath.RequireIntegrity = int.Parse(w[1]) == 1;
                                break;
                        }
                    }
                    if (hardenedPath.RequireIntegrity == null && hardenedPath.RequireMutualAuthentication == null && hardenedPath.RequirePrivacy == null)
                        continue;
                    lock (healthcheckData.GPOHardenedPath)
                    {
                        healthcheckData.GPOHardenedPath.Add(hardenedPath);
                    }
                }
            }
        }

        private void ExtractPowershellLogging(GPO GPO, RegistryPolReader reader)
        {
            int intvalue;
            if (reader.IsValueSet(@"Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging", "EnableModuleLogging", out intvalue))
            {
                GPPSecurityPolicy SecurityPolicy = null;
                foreach (GPPSecurityPolicy policy in healthcheckData.GPOLsaPolicy)
                {
                    if (policy.GPOId == GPO.InternalName)
                    {
                        SecurityPolicy = policy;
                        break;
                    }
                }
                if (SecurityPolicy == null)
                {
                    SecurityPolicy = new GPPSecurityPolicy();
                    SecurityPolicy.GPOName = GPO.DisplayName;
                    SecurityPolicy.GPOId = GPO.InternalName;

                    lock (healthcheckData.GPOLsaPolicy)
                    {
                        healthcheckData.GPOLsaPolicy.Add(SecurityPolicy);
                    }
                    SecurityPolicy.Properties = new List<GPPSecurityPolicyProperty>();
                }
                SecurityPolicy.Properties.Add(new GPPSecurityPolicyProperty("EnableModuleLogging", intvalue));
            }
            if (reader.IsValueSet(@"Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging", out intvalue))
            {
                GPPSecurityPolicy SecurityPolicy = null;
                foreach (GPPSecurityPolicy policy in healthcheckData.GPOLsaPolicy)
                {
                    if (policy.GPOId == GPO.InternalName)
                    {
                        SecurityPolicy = policy;
                        break;
                    }
                }
                if (SecurityPolicy == null)
                {
                    SecurityPolicy = new GPPSecurityPolicy();
                    SecurityPolicy.GPOName = GPO.DisplayName;
                    SecurityPolicy.GPOId = GPO.InternalName;

                    lock (healthcheckData.GPOLsaPolicy)
                    {
                        healthcheckData.GPOLsaPolicy.Add(SecurityPolicy);
                    }
                    SecurityPolicy.Properties = new List<GPPSecurityPolicyProperty>();
                }
                SecurityPolicy.Properties.Add(new GPPSecurityPolicyProperty("EnableScriptBlockLogging", intvalue));
            }
        }

        private void ExtractKerberosSettings(GPO GPO, RegistryPolReader reader)
        {
            int intvalue;
            if (reader.IsValueSet(@"Software\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters", "EnableCbacAndArmor", out intvalue) && intvalue >= 1)
            {
                if (reader.IsValueSet(@"Software\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters", "CbacAndArmorLevel", out intvalue))
                {
                    GPPSecurityPolicy SecurityPolicy = null;
                    foreach (GPPSecurityPolicy policy in healthcheckData.GPOLsaPolicy)
                    {
                        if (policy.GPOId == GPO.InternalName)
                        {
                            SecurityPolicy = policy;
                            break;
                        }
                    }
                    if (SecurityPolicy == null)
                    {
                        SecurityPolicy = new GPPSecurityPolicy();
                        SecurityPolicy.GPOName = GPO.DisplayName;
                        SecurityPolicy.GPOId = GPO.InternalName;

                        lock (healthcheckData.GPOLsaPolicy)
                        {
                            healthcheckData.GPOLsaPolicy.Add(SecurityPolicy);
                        }
                        SecurityPolicy.Properties = new List<GPPSecurityPolicyProperty>();
                    }
                    SecurityPolicy.Properties.Add(new GPPSecurityPolicyProperty("CbacAndArmorLevel", intvalue));
                }
            }
            if (reader.IsValueSet(@"Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters", "EnableCbacAndArmor", out intvalue))
            {
                GPPSecurityPolicy SecurityPolicy = null;
                foreach (GPPSecurityPolicy policy in healthcheckData.GPOLsaPolicy)
                {
                    if (policy.GPOId == GPO.InternalName)
                    {
                        SecurityPolicy = policy;
                        break;
                    }
                }
                if (SecurityPolicy == null)
                {
                    SecurityPolicy = new GPPSecurityPolicy();
                    SecurityPolicy.GPOName = GPO.DisplayName;
                    SecurityPolicy.GPOId = GPO.InternalName;

                    lock (healthcheckData.GPOLsaPolicy)
                    {
                        healthcheckData.GPOLsaPolicy.Add(SecurityPolicy);
                    }
                    SecurityPolicy.Properties = new List<GPPSecurityPolicyProperty>();
                }
                SecurityPolicy.Properties.Add(new GPPSecurityPolicyProperty("EnableCbacAndArmor", intvalue));
            }
        }

        private void ExtractFirewallRules(GPO GPO, RegistryPolReader reader)
        {
            foreach (var record in reader.SearchRecord(@"Software\Policies\Microsoft\WindowsFirewall\FirewallRules"))
            {
                if (record.Type != Microsoft.Win32.RegistryValueKind.String)
                {
                    Trace.WriteLine("Type for " + record.Key + " is not String: " + record.Type);
                    continue;
                }
                // gammar: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpfas/2efe0b76-7b4a-41ff-9050-1023f8196d16
                var stringvalue = UnicodeEncoding.Unicode.GetString(record.ByteValue).TrimEnd('\0');
                var values = stringvalue.Split('|');
                if (values.Length < 2)
                    continue;

                var fwRule = new GPPFireWallRule()
                {
                    GPOName = GPO.DisplayName,
                    GPOId = GPO.InternalName,
                    Version = values[0],
                    Id = record.Value,
                };
                foreach (var value in values)
                {
                    var v2 = value.Split('=');
                    if (v2.Length < 2)
                        continue; // ignore first field also which is version
                    // Action=Block|Active=TRUE|Dir=Out|RA4=1.0.0.0-9.255.255.255|RA4=11.0.0.0-126.255.255.255|Name=blocktointernet
                    switch (v2[0].ToLower())
                    {
                        case "action":
                            fwRule.Action = v2[1];
                            break;
                        case "active":
                            {
                                bool fwActive;
                                if (bool.TryParse(v2[1], out fwActive))
                                {
                                    fwRule.Active = fwActive;
                                }
                            }
                            break;
                        case "app":
                            fwRule.App = v2[1];
                            break;
                        case "dir":
                            fwRule.Direction = v2[1];
                            break;
                        case "name":
                            fwRule.Name = v2[1];
                            break;
                        case "lport":
                            fwRule.LPort = v2[1];
                            break;
                        case "rport":
                            fwRule.RPort = v2[1];
                            break;
                        case "lport2_10":
                            fwRule.LPort = v2[1];
                            break;
                        case "rport2_10":
                            fwRule.RPort = v2[1];
                            break;
                        case "protocol":
                            {
                                int protocol;
                                if (int.TryParse(v2[1], out protocol))
                                    fwRule.Protocol = protocol;
                            }
                            break;
                        case "ra4":
                        case "ra42":
                            {
                                if (fwRule.RA4 == null)
                                    fwRule.RA4 = new List<string>();
                                fwRule.RA4.Add(v2[1]);
                            }
                            break;
                        case "la4":
                        case "la42":
                            {
                                if (fwRule.LA4 == null)
                                    fwRule.LA4 = new List<string>();
                                fwRule.LA4.Add(v2[1]);
                            }
                            break;
                        case "ra6":
                        case "ra62":
                            {
                                if (fwRule.RA6 == null)
                                    fwRule.RA6 = new List<string>();
                                fwRule.RA6.Add(v2[1]);
                            }
                            break;
                        case "la6":
                        case "la62":
                            {
                                if (fwRule.LA6 == null)
                                    fwRule.LA6 = new List<string>();
                                fwRule.LA6.Add(v2[1]);
                            }
                            break;
                    }
                }
                lock (healthcheckData.GPPFirewallRules)
                {
                    healthcheckData.GPPFirewallRules.Add(fwRule);
                }
            }
        }

        private void ExtractEnableMulticast(GPO GPO, RegistryPolReader reader)
        {
            int intvalue;
            if (reader.IsValueSet(@"Software\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast", out intvalue))
            {
                GPPSecurityPolicy SecurityPolicy = null;
                foreach (GPPSecurityPolicy policy in healthcheckData.GPOLsaPolicy)
                {
                    if (policy.GPOId == GPO.InternalName)
                    {
                        SecurityPolicy = policy;
                        break;
                    }
                }
                if (SecurityPolicy == null)
                {
                    SecurityPolicy = new GPPSecurityPolicy();
                    SecurityPolicy.GPOName = GPO.DisplayName;
                    SecurityPolicy.GPOId = GPO.InternalName;

                    lock (healthcheckData.GPOLsaPolicy)
                    {
                        healthcheckData.GPOLsaPolicy.Add(SecurityPolicy);
                    }
                    SecurityPolicy.Properties = new List<GPPSecurityPolicyProperty>();
                }
                SecurityPolicy.Properties.Add(new GPPSecurityPolicyProperty("EnableMulticast", intvalue));
            }
        }

        private int ExtractScreenSavePolicy(GPO GPO, ref GPPSecurityPolicy PSO, RegistryPolReader reader)
        {
            int intvalue;
            //https://support.microsoft.com/en-us/kb/221784
            if (reader.IsValueSetIntAsStringValue(@"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "ScreenSaverGracePeriod", out intvalue))
            {
                if (PSO == null)
                {
                    PSO = new GPPSecurityPolicy();
                    PSO.GPOName = GPO.DisplayName;
                    PSO.GPOId = GPO.InternalName;
                    lock (healthcheckData.GPOScreenSaverPolicy)
                    {
                        healthcheckData.GPOScreenSaverPolicy.Add(PSO);
                    }
                    PSO.Properties = new List<GPPSecurityPolicyProperty>();
                }
                PSO.Properties.Add(new GPPSecurityPolicyProperty("ScreenSaverGracePeriod", intvalue));
            }

            return intvalue;
        }

        private void ProcessDefenderASRData(RegistryPolReader reader, GPO gPO)
        {
            int asr = 0;

            if (reader.IsValueSet(@"Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR", "ExploitGuard_ASR_Rules", out asr))
            {
                // ignore GPO if ASR is not enabled
                if (asr != 1)
                {
                    return;
                }
            }
            foreach (RegistryPolRecord record in reader.SearchRecord("Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules"))
            {
                var data = UnicodeEncoding.Unicode.GetString(record.ByteValue);
                var intdata = 0;
                int.TryParse(data, out intdata);
                var asrdata = new HealthcheckDefenderASRData()
                {
                    GPOId = gPO.InternalName,
                    GPOName = gPO.DisplayName,
                    ASRRule = record.Value,
                    Action = intdata,
                };
                lock (healthcheckData.GPODefenderASR)
                {
                    healthcheckData.GPODefenderASR.Add(asrdata);
                }
            }
        }

        delegate T Constructor<T>();
        private void ProcessWSUSData(RegistryPolReader reader, GPO gPO)
        {
            // https://docs.microsoft.com/de-de/security-updates/WindowsUpdateServices/18127499

            HealthcheckWSUSData data = null;

            Constructor<HealthcheckWSUSData> CreateIfNeeded = () =>
            {
                if (data == null)
                {
                    data = new HealthcheckWSUSData()
                    {
                        GPOId = gPO.InternalName,
                        GPOName = gPO.DisplayName,
                        Options = new List<HealthcheckWSUSDataOption>(),
                    };
                    lock (healthcheckData.GPOWSUS)
                    {
                        healthcheckData.GPOWSUS.Add(data);
                    }
                }
                return data;
            };

            string wsusserver;
            if (reader.IsValueSet(@"Software\Policies\Microsoft\Windows\WindowsUpdate", "WUStatusServer", out wsusserver))
            {
                CreateIfNeeded().WSUSserver = wsusserver;
            }
            if (reader.IsValueSet(@"Software\Policies\Microsoft\Windows\WindowsUpdate", "UpdateServiceUrlAlternate", out wsusserver))
            {
                CreateIfNeeded().WSUSserverAlternate = wsusserver;
            }
            int option;
            if (reader.IsValueSet(@"Software\Policies\Microsoft\Windows\WindowsUpdate\AU", "UseWUServer", out option))
            {
                CreateIfNeeded().Options.Add(new HealthcheckWSUSDataOption() { Name = "UseWUServer", Value = option, });
            }
            if (reader.IsValueSet(@"Software\Policies\Microsoft\Windows\WindowsUpdate\AU", "AUOptions", out option))
            {
                CreateIfNeeded().Options.Add(new HealthcheckWSUSDataOption() { Name = "AUOptions", Value = option, });
            }
            if (reader.IsValueSet(@"Software\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAutoUpdate", out option))
            {
                CreateIfNeeded().Options.Add(new HealthcheckWSUSDataOption() { Name = "NoAutoUpdate", Value = option, });
            }
            if (reader.IsValueSet(@"Software\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAutoRebootWithLoggedOnUsers", out option))
            {
                CreateIfNeeded().Options.Add(new HealthcheckWSUSDataOption() { Name = "NoAutoRebootWithLoggedOnUsers", Value = option, });
            }
            if (reader.IsValueSet(@"Software\Policies\Microsoft\Windows\WindowsUpdate", "SetProxyBehaviorForUpdateDetection", out option))
            {
                CreateIfNeeded().Options.Add(new HealthcheckWSUSDataOption() { Name = "SetProxyBehaviorForUpdateDetection", Value = option, });
            }
            if (reader.IsValueSet(@"Software\Policies\Microsoft\Windows\WindowsUpdate", "DoNotEnforceEnterpriseTLSCertPinningForUpdateDetection", out option))
            {
                CreateIfNeeded().Options.Add(new HealthcheckWSUSDataOption() { Name = "DoNotEnforceEnterpriseTLSCertPinningForUpdateDetection", Value = option, });
            }
        }

        private void GenerateWSUSData(ADDomainInfo domainInfo, ADWebService adws)
        {
            var cache = new Dictionary<string, KeyValuePair<List<string>, byte[]>>();
            foreach (var gpo in healthcheckData.GPOWSUS)
            {
                if (!string.IsNullOrEmpty(gpo.WSUSserver))
                {
                    Uri uri;
                    if (Uri.TryCreate(gpo.WSUSserver, UriKind.Absolute, out uri))
                    {
                        if (uri.Scheme == "https")
                        {
                            var key = uri.Host + ":" + uri.Port;
                            if (!cache.ContainsKey(key))
                            {
                                byte[] certificate;
                                var protocols = new List<string>();
                                GenerateTLSInfo(uri.Host, uri.Port, protocols, out certificate, "[" + DateTime.Now + "] ");
                                cache[key] = new KeyValuePair<List<string>, byte[]>(protocols, certificate);
                            }
                            gpo.WSUSserverSSLProtocol = cache[key].Key;
                            gpo.WSUSserverCertificate = cache[key].Value;
                        }
                    }
                }
                if (!string.IsNullOrEmpty(gpo.WSUSserverAlternate))
                {
                    Uri uri;
                    if (Uri.TryCreate(gpo.WSUSserverAlternate, UriKind.Absolute, out uri))
                    {
                        if (uri.Scheme == "https")
                        {
                            var key = uri.Host + ":" + uri.Port;
                            if (!cache.ContainsKey(key))
                            {
                                byte[] certificate;
                                var protocols = new List<string>();
                                GenerateTLSInfo(uri.Host, uri.Port, protocols, out certificate, "[" + DateTime.Now + "] ");
                                cache[key] = new KeyValuePair<List<string>, byte[]>(protocols, certificate);
                            }
                            gpo.WSUSserverAlternateSSLProtocol = cache[key].Key;
                            gpo.WSUSserverAlternateCertificate = cache[key].Value;
                        }
                    }
                }
            }
        }

        private void GenerateMSOLData(ADDomainInfo domainInfo, ADWebService adws)
        {
            // check for MSOL
            var EXT_RIGHT_REPLICATION_GET_CHANGES_ALL = new Guid("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2");
            // get all account with the right to replicate
            var msolSid = new List<string>();
            adws.Enumerate(domainInfo.DefaultNamingContext,
                                        "(objectClass=*)",
                                        new string[] { "nTSecurityDescriptor" }, (ADItem aditem) =>
                                        {
                                            ActiveDirectorySecurity sd = aditem.NTSecurityDescriptor;
                                            foreach (ActiveDirectoryAccessRule accessrule in sd.GetAccessRules(true, false, typeof(SecurityIdentifier)))
                                            {
                                                if (accessrule.AccessControlType != AccessControlType.Allow)
                                                    continue;
                                                if ((accessrule.ObjectFlags & ObjectAceFlags.ObjectAceTypePresent) == ObjectAceFlags.ObjectAceTypePresent)
                                                {
                                                    if ((accessrule.ActiveDirectoryRights & ActiveDirectoryRights.ExtendedRight) == ActiveDirectoryRights.ExtendedRight)
                                                    {
                                                        if (EXT_RIGHT_REPLICATION_GET_CHANGES_ALL == accessrule.ObjectType)
                                                        {
                                                            msolSid.Add(((SecurityIdentifier)accessrule.IdentityReference).Value);
                                                        }
                                                    }
                                                }
                                            }
                                        }, "Base");

            const string regex = "^Account created by Microsoft Azure Active Directory Connect with installation identifier (?<identifier>.+?) running on computer (?<computer>.+?) configured to synchronize to tenant (?<tenant>.+?). This account must have directory replication permissions in the local Active Directory and write permission on certain attributes to enable Hybrid Deployment\\.$";

            Regex re = new Regex(regex);
            healthcheckData.AzureADConnect = new List<HealthCheckMSOL>();

            foreach (var sid in msolSid)
            {
                adws.Enumerate(domainInfo.DefaultNamingContext,
                                        "(objectSid=" + ADConnection.EncodeSidToString(sid) + ")",
                                        new string[] {
                                            "distinguishedName",
                                            "description",
                                            "lastLogonTimestamp",
                                            "pwdLastSet",
                                            "samAccountName",
                                            "userAccountControl",
                                            "whenCreated",
                                        }, (ADItem aditem) =>
                                        {
                                            if (!string.IsNullOrEmpty(aditem.Description))
                                            {
                                                Match m = re.Match(aditem.Description);
                                                if (!m.Success)
                                                    return;
                                                var msol = new HealthCheckMSOL();
                                                msol.MSOLDN = aditem.DistinguishedName;
                                                msol.Identifier = m.Groups["identifier"].Captures[0].Value;
                                                msol.Computer = m.Groups["computer"].Captures[0].Value;
                                                msol.Tenant = m.Groups["tenant"].Captures[0].Value;
                                                msol.MSOLCreated = aditem.WhenCreated;
                                                msol.MSOLLastLogon = aditem.LastLogonTimestamp;
                                                msol.MSOLIsEnabled = (aditem.UserAccountControl & 0x00000002) == 0;
                                                msol.MSOLPwdLastSet = aditem.PwdLastSet;
                                                msol.Account = aditem.SAMAccountName;
                                                healthcheckData.AzureADConnect.Add(msol);
                                            }
                                        });
            }
            foreach (var msol in healthcheckData.AzureADConnect)
            {
                adws.Enumerate(domainInfo.DefaultNamingContext,
                                        "(samAccountName=" + ADConnection.EscapeLDAP(msol.Computer) + "$)",
                                        new string[] {
                                            "distinguishedName",
                                            "description",
                                            "lastLogonTimestamp",
                                            "pwdLastSet",
                                            "userAccountControl",
                                            "whenCreated",
                                        }, (ADItem aditem) =>
                                        {
                                            msol.ComputerDN = aditem.DistinguishedName;
                                            msol.ComputerCreated = aditem.WhenCreated;
                                            msol.ComputerLastLogon = aditem.LastLogonTimestamp;
                                            msol.ComputerIsEnabled = (aditem.UserAccountControl & 0x00000002) == 0;
                                            msol.ComputerPwdLastSet = aditem.PwdLastSet;
                                        });
            }
        }

        private KeyValuePair<SecurityIdentifier, string>? MatchesBadUsersToCheck(SecurityIdentifier sid)
        {
            if (sid.Value == "S-1-1-0")
            {
                return new KeyValuePair<SecurityIdentifier, string>(sid, GraphObjectReference.Everyone);
            }
            else if (sid.Value == "S-1-5-7")
            {
                return new KeyValuePair<SecurityIdentifier, string>(sid, GraphObjectReference.Anonymous);
            }
            else if (sid.Value == "S-1-5-11")
            {
                return new KeyValuePair<SecurityIdentifier, string>(sid, GraphObjectReference.AuthenticatedUsers);
            }
            else if (sid.Value == "S-1-5-32-545")
            {
                return new KeyValuePair<SecurityIdentifier, string>(sid, GraphObjectReference.Users);
            }
            else if (sid.IsWellKnown(WellKnownSidType.AccountDomainGuestsSid) || sid.IsWellKnown(WellKnownSidType.AccountDomainUsersSid) || sid.IsWellKnown(WellKnownSidType.AuthenticatedUserSid))
            {
                try
                {
                    return new KeyValuePair<SecurityIdentifier, string>(sid, ((NTAccount)sid.Translate(typeof(NTAccount))).Value);
                }
                catch (Exception)
                {
                    return new KeyValuePair<SecurityIdentifier, string>(sid, sid.Value);
                }
            }
            else if (healthcheckData.MachineAccountQuota > 0 && sid.IsWellKnown(WellKnownSidType.AccountComputersSid))
            {
                try
                {
                    return new KeyValuePair<SecurityIdentifier, string>(sid, ((NTAccount)sid.Translate(typeof(NTAccount))).Value);
                }
                catch (Exception)
                {
                    return new KeyValuePair<SecurityIdentifier, string>(sid, sid.Value);
                }
            }
            return null;
        }

        private void ExtractGPODelegation(IADConnection adws, string path, GPO GPO)
        {
            if (!adws.FileConnection.DirectoryExists(path))
                return;
            var dirs = adws.FileConnection.GetAllSubDirectories(path);
            dirs.Insert(0, path);
            foreach (var dirname in dirs)
            {
                try
                {
                    ExtractGPODelegationAnalyzeAccessControl(GPO, adws.FileConnection.GetDirectorySecurity(dirname), dirname, (path == dirname));
                }
                catch (Exception)
                {
                }
            }
            foreach (var filename in adws.FileConnection.GetAllSubFiles(path))
            {
                try
                {
                    ExtractGPODelegationAnalyzeAccessControl(GPO, adws.FileConnection.GetFileSecurity(filename), filename, false);
                }
                catch (Exception)
                {
                }
            }
        }

        void ExtractGPODelegationAnalyzeAccessControl(GPO GPO, FileSystemSecurity security, string name, bool includeInherited)
        {
            foreach (var value in AnalyzeFileSystemSecurity(security, includeInherited))
            {
                healthcheckData.GPODelegation.Add(new GPODelegationData()
                {
                    GPOName = GPO.DisplayName,
                    GPOId = GPO.InternalName,
                    Item = name,
                    Right = value.Key,
                    Account = value.Value,
                }
                );
            }
        }

        List<KeyValuePair<string, string>> AnalyzeFileSystemSecurity(FileSystemSecurity security, bool includeInherited)
        {
            var output = new List<KeyValuePair<string, string>>();
            var Owner = (SecurityIdentifier)security.GetOwner(typeof(SecurityIdentifier));
            var matchOwner = MatchesBadUsersToCheck(Owner);
            if (matchOwner.HasValue)
            {
                output.Add(new KeyValuePair<string, string>("Owner", matchOwner.Value.Value));
            }
            var accessRules = security.GetAccessRules(true, includeInherited, typeof(SecurityIdentifier));
            if (accessRules == null)
                return output;

            foreach (FileSystemAccessRule accessrule in accessRules)
            {
                if (accessrule.AccessControlType == AccessControlType.Deny)
                    continue;
                if ((FileSystemRights.Write & accessrule.FileSystemRights) == 0)
                    continue;

                var match = MatchesBadUsersToCheck((SecurityIdentifier)accessrule.IdentityReference);
                if (!match.HasValue)
                    continue;
                output.Add(new KeyValuePair<string, string>(accessrule.FileSystemRights.ToString(), match.Value.Value));
            }
            return output;
        }


        private void GetGPOList(ADDomainInfo domainInfo, ADWebService adws, Dictionary<string, GPO> GPOList)
        {
            string[] properties = new string[] {
                        "distinguishedName",
                        "name",
                        "displayName",
                        "flags",
            };

            WorkOnReturnedObjectByADWS callback =
                (ADItem x) =>
                {
                    string GPOName = x.Name.ToLowerInvariant();
                    if (!GPOList.ContainsKey(x.Name))
                        GPOList.Add(x.Name, new GPO()
                        {
                            InternalName = x.Name,
                            DisplayName = x.DisplayName,
                            IsDisabled = (x.Flags == 3),
                            DN = x.DistinguishedName,
                            AppliedTo = new List<string>(),
                            AppliedOrder = new List<int>(),
                        });
                };

            adws.Enumerate(domainInfo.DefaultNamingContext, "(objectClass=groupPolicyContainer)", properties, callback);

            string[] GPproperties = new string[] {
                        "distinguishedName",
                        "gPLink",
            };

            WorkOnReturnedObjectByADWS callback2 =
                (ADItem x) =>
                {
                    int precedance = 1;
                    foreach (var dn in x.GetApplicableGPO())
                    {
                        foreach (var gpo in GPOList.Keys)
                        {
                            if (string.Equals(GPOList[gpo].DN, dn, StringComparison.OrdinalIgnoreCase))
                            {
                                GPOList[gpo].AppliedTo.Add(x.DistinguishedName);
                                GPOList[gpo].AppliedOrder.Add(precedance);
                                break;
                            }
                        }
                        precedance++;
                    }
                };

            adws.Enumerate(domainInfo.DefaultNamingContext, "(gPLink=*)", GPproperties, callback2);

            adws.Enumerate("CN=Sites," + domainInfo.ConfigurationNamingContext, "(gPLink=*)", GPproperties, callback2);
        }

        private void ExtractGPOLoginScript(IADConnection adws, ADDomainInfo domainInfo, string directoryFullPath, GPO GPO)
        {
            foreach (string gpoType in new[] { "User", "Machine" })
            {
                foreach (string filename in new[] { "scripts.ini", "psscripts.ini" })
                {
                    string path = directoryFullPath + "\\" + gpoType + "\\Scripts\\" + filename;
                    if (adws.FileConnection.FileExists(path))
                    {
                        try
                        {
                            ParseGPOLoginScript(adws, domainInfo, path, GPO, gpoType, filename);
                        }
                        catch (Exception ex)
                        {
                            Trace.WriteLine("Unable to parse " + GPO.DisplayName + " " + filename);
                            Trace.WriteLine("Exception " + ex.Message);
                            Trace.WriteLine(ex.StackTrace);
                        }
                    }
                }
            }
        }

        private void ParseGPOLoginScript(IADConnection adws, ADDomainInfo domainInfo, string path, GPO GPO, string gpoType, string filename)
        {
            using (var file2 = adws.FileConnection.GetFileStream(path))
            using (var file = new StreamReader(file2))
            {
                string line = null;
                int state = 0;
                Dictionary<string, string> logonscript = new Dictionary<string, string>();
                Dictionary<string, string> logoffscript = new Dictionary<string, string>();
                while ((line = file.ReadLine()) != null)
                {
                    if (line.StartsWith("[Logon]", StringComparison.InvariantCultureIgnoreCase))
                    {
                        state = 1;
                    }
                    else if (line.StartsWith("[Logoff]", StringComparison.InvariantCultureIgnoreCase))
                    {
                        state = 2;
                    }
                    else if (line.StartsWith("[", StringComparison.InvariantCultureIgnoreCase))
                    {
                        state = 0;
                    }
                    else if (state > 0)
                    {
                        int pos = line.IndexOf('=');
                        if (pos >= 1)
                        {
                            string key = line.Substring(0, pos).ToLowerInvariant();
                            string value = line.Substring(pos + 1).Trim();
                            if (state == 1)
                            {
                                logonscript[key] = value;
                            }
                            else if (state == 2)
                            {
                                logoffscript[key] = value;
                            }
                        }
                    }
                }
                for (int i = 0; ; i++)
                {
                    if (!logonscript.ContainsKey(i + "cmdline"))
                    {
                        break;
                    }
                    HealthcheckGPOLoginScriptData loginscript = new HealthcheckGPOLoginScriptData();
                    loginscript.GPOName = GPO.DisplayName;
                    loginscript.GPOId = GPO.InternalName;
                    loginscript.Action = "Logon";
                    loginscript.Source = filename + " (" + (gpoType == "Machine" ? "Computer" : "User") + " section)";
                    loginscript.CommandLine = logonscript[i + "cmdline"];
                    loginscript.Delegation = CheckScriptPermission(adws, domainInfo, loginscript.CommandLine);
                    if (logonscript.ContainsKey(i + "parameters"))
                    {
                        loginscript.Parameters = logonscript[i + "parameters"];
                    }
                    lock (healthcheckData.GPOLoginScript)
                    {
                        healthcheckData.GPOLoginScript.Add(loginscript);
                    }
                }
                for (int i = 0; ; i++)
                {
                    if (!logoffscript.ContainsKey(i + "cmdline"))
                    {
                        break;
                    }
                    HealthcheckGPOLoginScriptData loginscript = new HealthcheckGPOLoginScriptData();
                    loginscript.GPOName = GPO.DisplayName;
                    loginscript.GPOId = GPO.InternalName;
                    loginscript.Action = "Logoff";
                    loginscript.Source = filename + " (" + (gpoType == "Machine" ? "Computer" : "User") + " section)";
                    loginscript.CommandLine = logoffscript[i + "cmdline"];
                    loginscript.Delegation = CheckScriptPermission(adws, domainInfo, loginscript.CommandLine);
                    if (logoffscript.ContainsKey(i + "parameters"))
                    {
                        loginscript.Parameters = logoffscript[i + "parameters"];
                    }
                    lock (healthcheckData.GPOLoginScript)
                    {
                        healthcheckData.GPOLoginScript.Add(loginscript);
                    }
                }
            }
        }

        private void ExtractGPPFile(IADConnection adws, string path, GPO GPO, ADDomainInfo domainInfo, string UserOrComputer)
        {
            XmlDocument doc = new XmlDocument();
            doc.Load(path);
            XmlNodeList nodeList = doc.SelectNodes("/Files/File");
            foreach (XmlNode node in nodeList)
            {
                XmlNode action = node.SelectSingleNode("Properties/@action");
                if (action == null)
                    continue;
                if (action.Value == "D")
                    continue;
                XmlNode fromPath = node.SelectSingleNode("Properties/@fromPath");
                if (fromPath == null)
                    continue;
                if (!fromPath.Value.StartsWith("\\\\"))
                    continue;
                var file = new GPPFileDeployed();
                file.GPOName = GPO.DisplayName;
                file.GPOId = GPO.InternalName;
                file.Type = "Files (" + UserOrComputer + " section)";
                file.FileName = fromPath.Value;
                file.Delegation = new List<HealthcheckScriptDelegationData>();
                healthcheckData.GPPFileDeployed.Add(file);
                if (adws.FileConnection.FileExists(file.FileName))
                {
                    var ac = adws.FileConnection.GetFileSecurity(file.FileName);
                    foreach (var value in AnalyzeFileSystemSecurity(ac, true))
                    {
                        file.Delegation.Add(new HealthcheckScriptDelegationData()
                        {
                            Account = value.Value,
                            Right = value.Key,
                        }
                        );
                    }
                }
            }
        }

        private void ExtractGPPPassword(IADConnection adws, string shortname, string fullname, GPO GPO, string alternateNameIfGPODoesNotExists)
        {
            string[] xpaths = null;
            string xpathUser = "Properties/@userName";
            string xpathNewName = null;
            switch (shortname)
            {
                case "groups.xml":
                    xpaths = new string[] { "/Groups/User" };
                    xpathNewName = "Properties/@newName";
                    break;
                case "services.xml":
                    xpaths = new string[] { "/NTServices/NTService" };
                    xpathUser = "Properties/@accountName";
                    break;
                case "scheduledtasks.xml":
                    xpaths = new string[] { "/ScheduledTasks/Task", "/ScheduledTasks/ImmediateTask", "/ScheduledTasks/TaskV2", "/ScheduledTasks/ImmediateTaskV2" };
                    xpathUser = "Properties/@runAs";
                    break;
                case "datasources.xml":
                    xpaths = new string[] { "/DataSources/DataSource" };
                    break;
                case "printers.xml":
                    xpaths = new string[] { "/Printers/SharedPrinter" };
                    break;
                case "drives.xml":
                    xpaths = new string[] { "/Drives/Drive" };
                    break;
                default:
                    return;
            }

            XmlDocument doc = new XmlDocument();
            doc.Load(fullname);
            foreach (string xpath in xpaths)
            {
                XmlNodeList nodeList = doc.SelectNodes(xpath);
                foreach (XmlNode node in nodeList)
                {
                    XmlNode password = node.SelectSingleNode("Properties/@cpassword");
                    // no password
                    if (password == null)
                        continue;
                    // password has been manually changed
                    if (String.IsNullOrEmpty(password.Value))
                        continue;
                    GPPPassword PasswordData = new GPPPassword();
                    PasswordData.GPOName = (GPO == null ? alternateNameIfGPODoesNotExists : GPO.DisplayName);
                    PasswordData.GPOId = (GPO == null ? null : GPO.InternalName);
                    PasswordData.Password = DecodeGPPPassword(password.Value);

                    XmlNode userNameNode = node.SelectSingleNode(xpathUser);
                    PasswordData.UserName = (userNameNode != null ? userNameNode.Value : string.Empty);

                    XmlNode changed = node.SelectSingleNode("@changed");
                    if (changed != null)
                    {
                        PasswordData.Changed = DateTime.Parse(changed.Value);
                    }
                    else
                    {
                        PasswordData.Changed = adws.FileConnection.GetLastWriteTime(fullname);
                    }
                    if (xpathNewName != null)
                    {
                        XmlNode newNameNode = node.SelectSingleNode(xpathNewName);
                        if (newNameNode != null && !String.IsNullOrEmpty(newNameNode.Value))
                        {
                            PasswordData.Other = "NewName:" + newNameNode.Value;
                        }
                    }
                    XmlNode pathNode = node.SelectSingleNode("Properties/@path");
                    if (pathNode != null && !String.IsNullOrEmpty(pathNode.Value))
                    {
                        PasswordData.Other = "Path:" + pathNode.Value;
                    }
                    PasswordData.Type = shortname;
                    lock (healthcheckData.GPPPassword)
                    {
                        healthcheckData.GPPPassword.Add(PasswordData);
                    }
                }
            }
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2202:Ne pas supprimer d'objets plusieurs fois")]
        private string DecodeGPPPassword(string encryptedPassword)
        {
            byte[] aesKey = {0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
                                 0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b};
            string decrypted = null;
            switch (encryptedPassword.Length % 4)
            {
                case 2:
                    encryptedPassword += "==";
                    break;
                case 3:
                    encryptedPassword += "=";
                    break;
            }
            byte[] buffer = Convert.FromBase64String(encryptedPassword);
            try
            {
                using (Rijndael aes = new RijndaelManaged())
                {
                    aes.Key = aesKey;
                    aes.IV = new byte[aes.IV.Length];
                    var transform = aes.CreateDecryptor();
                    using (var ms = new System.IO.MemoryStream())
                    {
                        using (var cs = new CryptoStream(ms, transform, CryptoStreamMode.Write))
                        {
                            cs.Write(buffer, 0, buffer.Length);
                            cs.FlushFinalBlock();
                            decrypted = Encoding.Unicode.GetString(ms.ToArray());
                            cs.Close();
                            ms.Close();
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Trace.WriteLine("Unable to decrypt " + encryptedPassword);
                Trace.WriteLine(ex.Message);
                Trace.WriteLine(ex.StackTrace);
                return encryptedPassword;
            }
            return decrypted;
        }

        private void ExtractGPPPrivilegePasswordLsaSettingEtc(ADWebService adws, string filename, GPO GPO, ADDomainInfo domainInfo)
        {
            using (var file2 = adws.FileConnection.GetFileStream(filename))
            using (var file = new StreamReader(file2))
            {
                string line;
                while ((line = file.ReadLine()) != null)
                {
                    SubExtractPrivilege(adws, line, GPO);
                    SubExtractDCGPOPrivilege(adws, line, GPO);
                    SubExtractLsaSettings(line, GPO);
                    SubExtractLsaSettingsBis(line, GPO);
                    SubExtractPasswordSettings(line, GPO);
                    SubExtractGroupMembership(adws, line, GPO, domainInfo);
                    SubExtractSimpleAuditData(line, GPO);
                }
            }
        }

        private void SubExtractGroupMembership(ADWebService adws, string line, GPO GPO, ADDomainInfo domainInfo)
        {
            try
            {
                bool found = false;
                bool MemberOf = false;
                if (line.IndexOf("__MemberOf", StringComparison.OrdinalIgnoreCase) > 0)
                {
                    found = true;
                    MemberOf = true;
                }
                else if (line.IndexOf("__Members", StringComparison.OrdinalIgnoreCase) > 0)
                {
                    found = true;
                }
                if (!found)
                    return;
                int index = line.IndexOf("=");
                if (index < 0)
                    return;
                string rights = line.Substring(index + 1).TrimStart();
                if (String.IsNullOrEmpty(rights))
                    return;
                string left = line.Substring(0, line.IndexOf("__"));

                foreach (string right in rights.Split(','))
                {

                    string user1 = right.Trim();
                    // ignore some well known accounts to save space
                    if (user1.StartsWith("*S-1") && user1.EndsWith("-512"))
                        continue;
                    if (user1.StartsWith("*S-1") && user1.EndsWith("-510"))
                        continue;
                    if (user1 == "*S-1-1-0")
                    {
                        user1 = GraphObjectReference.Everyone;
                    }
                    else if (user1 == "*S-1-5-7")
                    {
                        user1 = GraphObjectReference.Anonymous;
                    }
                    else if (user1 == "*S-1-5-11")
                    {
                        user1 = GraphObjectReference.AuthenticatedUsers;
                    }
                    else if (user1 == "*S-1-5-32-545")
                    {
                        user1 = GraphObjectReference.Users;
                    }
                    else if (user1.StartsWith("*S-1-5-") && user1.EndsWith("-513"))
                    {
                        user1 = GraphObjectReference.DomainUsers;
                    }
                    else if (user1.StartsWith("*S-1-5-") && user1.EndsWith("-515"))
                    {
                        user1 = GraphObjectReference.DomainComputers;
                    }
                    else if (user1.StartsWith("*S-1", StringComparison.InvariantCultureIgnoreCase))
                    {
                        user1 = adws.ConvertSIDToName(user1.Substring(1));
                    }
                    string user2 = left.Trim();
                    if (user2 == "*S-1-1-0")
                    {
                        user2 = GraphObjectReference.Everyone;
                    }
                    else if (user2 == "*S-1-5-7")
                    {
                        user2 = GraphObjectReference.Anonymous;
                    }
                    else if (user2 == "*S-1-5-11")
                    {
                        user2 = GraphObjectReference.AuthenticatedUsers;
                    }
                    else if (user2 == "*S-1-5-32-545")
                    {
                        user2 = GraphObjectReference.Users;
                    }
                    else if (user2.StartsWith("*S-1-5-") && user2.EndsWith("-513"))
                    {
                        user2 = GraphObjectReference.DomainUsers;
                    }
                    else if (user2.StartsWith("*S-1-5-") && user2.EndsWith("-515"))
                    {
                        user2 = GraphObjectReference.DomainComputers;
                    }
                    else if (user2.StartsWith("*S-1", StringComparison.InvariantCultureIgnoreCase))
                    {
                        user2 = adws.ConvertSIDToName(user2.Substring(1));
                    }
                    GPOMembership membership = new GPOMembership();
                    lock (healthcheckData.GPOLocalMembership)
                    {
                        healthcheckData.GPOLocalMembership.Add(membership);
                    }
                    membership.GPOName = GPO.DisplayName;
                    membership.GPOId = GPO.InternalName;
                    if (MemberOf)
                    {
                        membership.User = user2;
                        membership.MemberOf = user1;
                    }
                    else
                    {
                        membership.User = user1;
                        membership.MemberOf = user2;
                    }
                }
            }
            catch (Exception ex)
            {
                Trace.WriteLine("Exception " + ex.Message + " while analysing membership of " + GPO.DisplayName);
            }
        }

        // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/01f8e057-f6a8-4d6e-8a00-99bcd241b403
        private void SubExtractSimpleAuditData(string line, GPO GPO)
        {
            string[] AuditSettings = new string[] {
                "AuditSystemEvents",
                "AuditLogonEvents",
                "AuditPrivilegeUse",
                "AuditPolicyChange",
                "AuditAccountManage",
                "AuditProcessTracking",
                "AuditDSAccess",
                "AuditObjectAccess",
                "AuditAccountLogon",
            };
            foreach (string auditSetting in AuditSettings)
            {
                if (line.StartsWith(auditSetting, StringComparison.InvariantCultureIgnoreCase))
                {
                    int pos = line.IndexOf('=') + 1;
                    if (pos > 1)
                    {
                        var a = new GPOAuditSimpleData()
                        {
                            GPOId = GPO.InternalName,
                            GPOName = GPO.DisplayName,
                            Category = auditSetting,
                            Value = int.Parse(line.Substring(pos)),
                        };
                        lock (healthcheckData.GPOAuditSimple)
                        {
                            healthcheckData.GPOAuditSimple.Add(a);
                        }
                    }
                }
            }
        }

        private void SubExtractPasswordSettings(string line, GPO GPO)
        {
            string[] PasswordSettings = new string[] {
                "MinimumPasswordAge",
                "MaximumPasswordAge",
                "MinimumPasswordLength",
                "PasswordComplexity",
                "PasswordHistorySize",
                "LockoutBadCount",
                "ResetLockoutCount",
                "LockoutDuration",
                //"RequireLogonToChangePassword",
                //"ForceLogoffWhenHourExpire",
                "ClearTextPassword",
            };

            foreach (string passwordSetting in PasswordSettings)
            {
                if (line.StartsWith(passwordSetting, StringComparison.InvariantCultureIgnoreCase))
                {
                    int pos = line.IndexOf('=') + 1;
                    if (pos > 1)
                    {
                        lock (healthcheckData.GPPPasswordPolicy)
                        {
                            GPPSecurityPolicy PSO = null;
                            foreach (GPPSecurityPolicy policy in healthcheckData.GPPPasswordPolicy)
                            {
                                if (policy.GPOId == GPO.InternalName)
                                {
                                    PSO = policy;
                                    break;
                                }
                            }
                            if (PSO == null)
                            {
                                PSO = new GPPSecurityPolicy();
                                PSO.GPOName = GPO.DisplayName;
                                PSO.GPOId = GPO.InternalName;
                                healthcheckData.GPPPasswordPolicy.Add(PSO);
                                PSO.Properties = new List<GPPSecurityPolicyProperty>();
                            }
                            int value = int.Parse(line.Substring(pos).Trim());
                            PSO.Properties.Add(new GPPSecurityPolicyProperty(passwordSetting, value));
                        }
                    }
                }
            }
        }

        private void SubExtractLsaSettings(string line, GPO GPO)
        {
            string[] LsaSettings = new string[] {
                @"EveryoneIncludesAnonymous",
                @"ForceGuest",
                @"LimitBlankPasswordUse",
                @"LmCompatibilityLevel",
                //@"NTLMMinClientSec",
                //@"NTLMMinServerSec",
                @"NoLMHash",
                @"RestrictAnonymous",
                @"RestrictAnonymousSAM",
                @"MSV1_0\RestrictSendingNTLMTraffic",
            };
            if (line.StartsWith(@"MACHINE\System\CurrentControlSet\Control\Lsa\", StringComparison.InvariantCultureIgnoreCase))
            {
                int pos = line.IndexOf('=') + 1;
                if (pos > 1)
                {
                    string[] values = line.Substring(pos).Trim().Split(',');
                    if (values.Length == 2)
                    {
                        foreach (string lsasetting in LsaSettings)
                        {
                            if (line.ToLowerInvariant().Contains(lsasetting.ToLowerInvariant()))
                            {
                                int value = int.Parse(values[1]);
                                // eliminate false positive
                                if (lsasetting == "EveryoneIncludesAnonymous" && value == 0)
                                    continue;
                                if (lsasetting == "ForceGuest" && value == 0)
                                    continue;
                                if (lsasetting == "LimitBlankPasswordUse" && value == 1)
                                    continue;
                                //if (lsasetting == "LmCompatibilityLevel" && (value == 3 || value == 5))
                                //    continue;
                                if (lsasetting == "NoLMHash" && value == 1)
                                    continue;
                                if (lsasetting == "RestrictAnonymous" && value >= 1)
                                    continue;
                                if (lsasetting == "RestrictAnonymousSAM" && value == 1)
                                    continue;
                                AddGPOLsaPolicy(GPO, lsasetting, value);
                            }
                        }
                    }
                }
            }
            else if (line.StartsWith(@"MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SecurityLevel=4,1", StringComparison.InvariantCultureIgnoreCase))
            {
                AddGPOLsaPolicy(GPO, "recoveryconsole_securitylevel", 1);
            }
            else if (line.StartsWith(@"MACHINE\System\CurrentControlSet\Services\LDAP\LDAPClientIntegrity=4,0", StringComparison.InvariantCultureIgnoreCase))
            {
                AddGPOLsaPolicy(GPO, "LDAPClientIntegrity", 0);
            }
            else if (line.StartsWith(@"MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RefusePasswordChange=4,1", StringComparison.InvariantCultureIgnoreCase))
            {
                AddGPOLsaPolicy(GPO, "RefusePasswordChange", 1);
            }
            else if (line.StartsWith(@"MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature=4,0", StringComparison.InvariantCultureIgnoreCase))
            {
                AddGPOLsaPolicy(GPO, "EnableSecuritySignature", 0);
            }
            else if (line.StartsWith(@"MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\SupportedEncryptionTypes=4,", StringComparison.InvariantCultureIgnoreCase))
            {
                AddGPOLsaPolicy(GPO, "SupportedEncryptionTypes", (int)uint.Parse(line.Split(',')[1]));
            }
        }

        private void AddGPOLsaPolicy(GPO GPO, string setting, int value)
        {
            lock (healthcheckData.GPOLsaPolicy)
            {
                GPPSecurityPolicy PSO = null;
                foreach (GPPSecurityPolicy policy in healthcheckData.GPOLsaPolicy)
                {
                    if (policy.GPOId == GPO.InternalName)
                    {
                        PSO = policy;
                        break;
                    }
                }
                if (PSO == null)
                {
                    PSO = new GPPSecurityPolicy();
                    PSO.GPOName = GPO.DisplayName;
                    PSO.GPOId = GPO.InternalName;
                    healthcheckData.GPOLsaPolicy.Add(PSO);
                    PSO.Properties = new List<GPPSecurityPolicyProperty>();
                }
                PSO.Properties.Add(new GPPSecurityPolicyProperty(setting, value));
            }
        }


        private void SubExtractLsaSettingsBis(string line, GPO GPO)
        {
            string[] LsaSettings = new string[] {
                @"LSAAnonymousNameLookup",
                @"EnableGuestAccount",
            };
            foreach (string lsasetting in LsaSettings)
            {
                if (line.StartsWith(lsasetting, StringComparison.InvariantCultureIgnoreCase))
                {
                    int pos = line.IndexOf('=') + 1;
                    if (pos > 1)
                    {
                        int value = int.Parse(line.Substring(pos).Trim());
                        if (lsasetting == "EnableGuestAccount" && value == 0)
                            continue;
                        if (lsasetting == "LSAAnonymousNameLookup" && value == 0)
                            continue;
                        lock (healthcheckData.GPOLsaPolicy)
                        {
                            GPPSecurityPolicy PSO = null;
                            foreach (GPPSecurityPolicy policy in healthcheckData.GPOLsaPolicy)
                            {
                                if (policy.GPOId == GPO.InternalName)
                                {
                                    PSO = policy;
                                    break;
                                }
                            }
                            if (PSO == null)
                            {
                                PSO = new GPPSecurityPolicy();
                                PSO.GPOName = GPO.DisplayName;
                                PSO.GPOId = GPO.InternalName;
                                healthcheckData.GPOLsaPolicy.Add(PSO);
                                PSO.Properties = new List<GPPSecurityPolicyProperty>();
                            }
                            PSO.Properties.Add(new GPPSecurityPolicyProperty(lsasetting, value));
                        }
                    }
                }
            }
        }

        public const string EmptyUserPrivilege = "<empty>";
        private void SubExtractPrivilege(ADWebService adws, string line, GPO GPO)
        {
            string[] privileges = new string[] {
                "SeBackupPrivilege",
                "SeCreateTokenPrivilege",
                "SeDebugPrivilege",
                "SeEnableDelegationPrivilege",
                "SeSyncAgentPrivilege",
                "SeTakeOwnershipPrivilege",
                "SeTcbPrivilege",
                "SeTrustedCredManAccessPrivilege",
                "SeMachineAccountPrivilege",
                "SeLoadDriverPrivilege",
                "SeRestorePrivilege",
                "SeImpersonatePrivilege",
                "SeAssignPrimaryTokenPrivilege",
                "SeSecurityPrivilege",
                "SeManageVolumePrivilege",
            };
            foreach (string privilege in privileges)
            {
                if (line.StartsWith(privilege, StringComparison.InvariantCultureIgnoreCase))
                {
                    int pos = line.IndexOf('=') + 1;
                    if (pos > 1)
                    {
                        string value = line.Substring(pos).Trim();
                        string[] values = value.Split(',');
                        // special case: this unset previous values
                        foreach (string user in values)
                        {
                            var user2 = ConvertGPOUserToUserFriendlyUser(adws, user);
                            // ignore empty privilege assignment
                            if (String.IsNullOrEmpty(user2))
                                user2 = EmptyUserPrivilege;

                            GPPRightAssignment right = new GPPRightAssignment();
                            lock (healthcheckData.GPPRightAssignment)
                            {
                                healthcheckData.GPPRightAssignment.Add(right);
                            }
                            right.GPOName = GPO.DisplayName;
                            right.GPOId = GPO.InternalName;
                            right.Privilege = privilege;
                            right.User = user2;
                        }

                    }
                }
            }
        }

        private void SubExtractDCGPOPrivilege(ADWebService adws, string line, GPO GPO)
        {
            string[] privileges = new string[] {
                "SeInteractiveLogonRight",
                "SeRemoteInteractiveLogonRight",
                "SeNetworkLogonRight",
                "SeServiceLogonRight",
                "SeBatchLogonRight",
                "SeDenyServiceLogonRight",
                "SeDenyRemoteInteractiveLogonRight",
                "SeDenyNetworkLogonRight",
                "SeDenyInteractiveLogonRight",
                "SeDenyBatchLogonRight",
            };
            foreach (string privilege in privileges)
            {
                if (line.StartsWith(privilege, StringComparison.InvariantCultureIgnoreCase))
                {
                    int pos = line.IndexOf('=') + 1;
                    if (pos > 1)
                    {
                        string value = line.Substring(pos).Trim();
                        string[] values = value.Split(',');
                        foreach (string user in values)
                        {
                            var user2 = ConvertGPOUserToUserFriendlyUser(adws, user);
                            // ignore empty privilege assignment
                            if (String.IsNullOrEmpty(user2))
                                continue;

                            GPPRightAssignment right = new GPPRightAssignment();
                            lock (healthcheckData.GPPLoginAllowedOrDeny)
                            {
                                healthcheckData.GPPLoginAllowedOrDeny.Add(right);
                            }
                            right.GPOName = GPO.DisplayName;
                            right.GPOId = GPO.InternalName;
                            right.Privilege = privilege;
                            right.User = user2;
                        }

                    }
                }
            }
        }

        private string ConvertGPOUserToUserFriendlyUser(ADWebService adws, string user)
        {
            /*// ignore well known sid
			// 
			if (user.StartsWith("*S-1-5-32-", StringComparison.InvariantCultureIgnoreCase))
			{
				return null;
			}
			// Local system
			if (user.StartsWith("*S-1-5-18", StringComparison.InvariantCultureIgnoreCase))
			{
				return null;
			}
			// SERVICE
			if (user.StartsWith("*S-1-5-6", StringComparison.InvariantCultureIgnoreCase))
			{
				return null;
			}
			// LOCAL_SERVICE
			if (user.StartsWith("*S-1-5-19", StringComparison.InvariantCultureIgnoreCase))
			{
				return null;
			}
			// NETWORK_SERVICE
			if (user.StartsWith("*S-1-5-20", StringComparison.InvariantCultureIgnoreCase))
			{
				return null;
			}
			*/
            if (user == "*S-1-1-0")
            {
                return GraphObjectReference.Everyone;
            }
            else if (user == "*S-1-5-7")
            {
                return GraphObjectReference.Anonymous;
            }
            else if (user == "*S-1-5-11")
            {
                return GraphObjectReference.AuthenticatedUsers;
            }
            else if (user == "*S-1-5-32-545")
            {
                return GraphObjectReference.Users;
            }
            else if (user == "*S-1-5-32-544")
            {
                return GraphObjectReference.Administrators;
            }
            else if (user.StartsWith("*S-1", StringComparison.InvariantCultureIgnoreCase))
            {
                if (user.EndsWith("-513"))
                {
                    return GraphObjectReference.DomainUsers;
                }
                else if (user.EndsWith("-515"))
                {
                    return GraphObjectReference.DomainComputers;
                }
                else if (user.EndsWith("-512"))
                {
                    return GraphObjectReference.DomainAdministrators;
                }
                else
                {
                    return adws.ConvertSIDToName(user.Substring(1));
                }
            }
            else
            {
                return user;
            }
        }

        private void ExtractGPOAudit(IADConnection adws, string path, GPO GPO, ADDomainInfo domainInfo)
        {
            try
            {
                using (var file2 = adws.FileConnection.GetFileStream(path))
                using (var tr = new StreamReader(file2))
                {
                    // skip first line
                    string line = tr.ReadLine();
                    if (line == null)
                        return;
                    while ((line = tr.ReadLine()) != null)
                    {
                        var b = line.Split(',');
                        if (b.Length < 7)
                            continue;
                        var sub = b[3];
                        if (string.IsNullOrEmpty(sub))
                            continue;
                        var a = new GPOAuditAdvancedData()
                        {
                            GPOId = GPO.InternalName,
                            GPOName = GPO.DisplayName,
                            SubCategory = new Guid(sub),
                            Value = int.Parse(b[6]),
                        };
                        lock (healthcheckData.GPOAuditAdvanced)
                        {
                            healthcheckData.GPOAuditAdvanced.Add(a);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Trace.WriteLine("Exception when analyzing GPO " + ex.Message);
            }
        }

        private void GeneratePSOData(ADDomainInfo domainInfo, ADWebService adws)
        {
            if (healthcheckData.GPPPasswordPolicy == null)
                healthcheckData.GPPPasswordPolicy = new List<GPPSecurityPolicy>();
            // adding the domain sid
            string[] properties = new string[] {
                        "distinguishedName",
                        "name",
                        "msDS-MinimumPasswordAge",
                        "msDS-MaximumPasswordAge",
                        "msDS-MinimumPasswordLength",
                        "msDS-PasswordComplexityEnabled",
                        "msDS-PasswordHistoryLength",
                        "msDS-LockoutThreshold",
                        "msDS-LockoutObservationWindow",
                        "msDS-LockoutDuration",
                        "msDS-PasswordReversibleEncryptionEnabled",
            };

            WorkOnReturnedObjectByADWS callback =
                (ADItem x) =>
                {
                    GPPSecurityPolicy PSO = new GPPSecurityPolicy();
                    PSO.GPOName = "PSO:" + x.Name;
                    healthcheckData.GPPPasswordPolicy.Add(PSO);
                    PSO.Properties = new List<GPPSecurityPolicyProperty>();
                    PSO.Properties.Add(new GPPSecurityPolicyProperty("MinimumPasswordAge", (int)(x.msDSMinimumPasswordAge / -864000000000)));
                    if (x.msDSMaximumPasswordAge == -9223372036854775808)
                        PSO.Properties.Add(new GPPSecurityPolicyProperty("MaximumPasswordAge", -1));
                    else
                        PSO.Properties.Add(new GPPSecurityPolicyProperty("MaximumPasswordAge", (int)(x.msDSMaximumPasswordAge / -864000000000)));
                    PSO.Properties.Add(new GPPSecurityPolicyProperty("MinimumPasswordLength", x.msDSMinimumPasswordLength));
                    if (x.msDSPasswordComplexityEnabled)
                        PSO.Properties.Add(new GPPSecurityPolicyProperty("PasswordComplexity", 1));
                    else
                        PSO.Properties.Add(new GPPSecurityPolicyProperty("PasswordComplexity", 0));
                    PSO.Properties.Add(new GPPSecurityPolicyProperty("PasswordHistorySize", x.msDSPasswordHistoryLength));
                    PSO.Properties.Add(new GPPSecurityPolicyProperty("LockoutBadCount", x.msDSLockoutThreshold));
                    PSO.Properties.Add(new GPPSecurityPolicyProperty("ResetLockoutCount", (int)(x.msDSLockoutObservationWindow / -600000000)));
                    PSO.Properties.Add(new GPPSecurityPolicyProperty("LockoutDuration", (int)(x.msDSLockoutDuration / -600000000)));
                    if (x.msDSPasswordReversibleEncryptionEnabled)
                        PSO.Properties.Add(new GPPSecurityPolicyProperty("ClearTextPassword", 1));
                    else
                        PSO.Properties.Add(new GPPSecurityPolicyProperty("ClearTextPassword", 0));
                };

            adws.Enumerate(domainInfo.DefaultNamingContext, "(&(objectClass=msDS-PasswordSettings)(msDS-PSOAppliesTo=*))", properties, callback);
        }

        [SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        private void GenerateAnomalies(ADDomainInfo domainInfo, ADWebService adws)
        {
            CheckADBackup(domainInfo, adws);

            CheckKrbtgtPwdChange(domainInfo, adws);

            CheckAdminSDHolderNotOK(domainInfo, adws);

            CheckSmartCard(domainInfo, adws);

            CheckPreWindows2000Group(domainInfo, adws);

            CheckDsHeuristics(domainInfo, adws);

            CheckSIDHistoryAuditingGroupPresent(domainInfo, adws);

            CheckDCOwners(domainInfo, adws);

            CheckPrivExchange(domainInfo, adws);

            CheckSchemaVulnerable(domainInfo, adws);

            CheckUnixPassword(domainInfo, adws);

            CheckLDAPIpDenyList(domainInfo, adws);

            CheckJavaTrustedData(domainInfo, adws);

            CheckServicePointData(domainInfo, adws);

            CheckDisplaySpecifier(domainInfo, adws);

            CheckWellKnownObjects(domainInfo, adws);
        }

        private void CheckKrbtgtPwdChange(ADDomainInfo domainInfo, ADWebService adws)
        {
            string[] propertieskrbtgt = new string[] { "distinguishedName", "replPropertyMetaData", "pwdLastSet" };
            adws.Enumerate(domainInfo.DefaultNamingContext, "(objectSid=" + ADConnection.EncodeSidToString(domainInfo.DomainSid.Value + "-502") + ")", propertieskrbtgt,
                (ADItem aditem) =>
                {
                    Trace.WriteLine("krbtgt found");
                    healthcheckData.KrbtgtLastChangeDate = aditem.PwdLastSet;

                    if (aditem.ReplPropertyMetaData == null)
                        return;
                    healthcheckData.KrbtgtLastVersion = aditem.ReplPropertyMetaData[0x9005A].Version;
                    if (healthcheckData.KrbtgtLastChangeDate < aditem.ReplPropertyMetaData[0x9005A].LastOriginatingChange)
                    {
                        healthcheckData.KrbtgtLastChangeDate = aditem.ReplPropertyMetaData[0x9005A].LastOriginatingChange;
                    }
                }
            );
        }

        private void CheckADBackup(ADDomainInfo domainInfo, ADWebService adws)
        {
            healthcheckData.LastADBackup = DateTime.MaxValue;

            string[] propertiesRoot = new string[] { "distinguishedName", "replPropertyMetaData" };
            adws.Enumerate(domainInfo.DefaultNamingContext, "(objectClass=*)", propertiesRoot,
                (ADItem aditem) =>
                {
                    // check replication data for dsaSignature
                    if (aditem.ReplPropertyMetaData != null && aditem.ReplPropertyMetaData.ContainsKey(0x2004A))
                        healthcheckData.LastADBackup = aditem.ReplPropertyMetaData[0x2004A].LastOriginatingChange;

                }
            , "Base");
        }

        private LAPSAnalyzer CheckLAPSInstalled(ADDomainInfo domainInfo, ADWebService adws)
        {
            var lapsAnalyzer = new LAPSAnalyzer(adws);

            healthcheckData.LAPSInstalled = lapsAnalyzer.LegacyLAPSInstalled;
            healthcheckData.NewLAPSInstalled = lapsAnalyzer.MsLAPSInstalled;

            if (lapsAnalyzer.LAPSInstalled)
            {
                healthcheckData.ListLAPSJoinedComputersToReview = new List<HealthcheckAccountDetailData>();

                string[] propertiesLapsCreated = new string[] {
                    "whenCreated",
                    "mS-DS-CreatorSID",
                    "distinguishedName",
                    "nTSecurityDescriptor",
                    "replPropertyMetaData",
                    "SAMAccountName",
                    "LastLogonTimestamp",
                    "PwdLastSet"
                };
                // search for enabled computers with creatorsid attribute filled
                adws.Enumerate(domainInfo.DefaultNamingContext, "(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(mS-DS-CreatorSID=*))", propertiesLapsCreated,
                    (ADItem x) =>
                    {
                        var f = false;
                        if (x.ReplPropertyMetaData == null)
                            return;
                        // check if there is a LAPS attribute (looked into metadata because hidden if the current user has not right to read it)
                        if (
                            (lapsAnalyzer.LegacyLAPSIntId != 0 && x.ReplPropertyMetaData.ContainsKey(lapsAnalyzer.LegacyLAPSIntId))
                            ||
                            (lapsAnalyzer.MsLAPSIntId != 0 && x.ReplPropertyMetaData.ContainsKey(lapsAnalyzer.MsLAPSIntId))
                            ||
                            (lapsAnalyzer.MsLAPSEncryptedIntId != 0 && x.ReplPropertyMetaData.ContainsKey(lapsAnalyzer.MsLAPSEncryptedIntId))
                            )
                        {
                            if (x.NTSecurityDescriptor != null)
                            {
                                // look for permissions that match the CreatorSID attribute
                                if (x.NTSecurityDescriptor.GetOwner(typeof(SecurityIdentifier)) == x.msDSCreatorSID)
                                {
                                    f = true;
                                }
                                else
                                {
                                    // look for explicit autorization granted to the user who created the object
                                    foreach (ActiveDirectoryAccessRule accessrule in x.NTSecurityDescriptor.GetAccessRules(true, false, typeof(SecurityIdentifier)))
                                    {
                                        if (accessrule.IdentityReference != x.msDSCreatorSID)
                                            continue;
                                        if ((accessrule.ActiveDirectoryRights & ActiveDirectoryRights.WriteDacl) == ActiveDirectoryRights.WriteDacl ||
                                            (accessrule.ActiveDirectoryRights & ActiveDirectoryRights.WriteOwner) == ActiveDirectoryRights.WriteOwner ||
                                            (accessrule.ActiveDirectoryRights & ActiveDirectoryRights.GenericWrite) == ActiveDirectoryRights.GenericWrite)
                                        {
                                            f = true;
                                            break;
                                        }
                                        // all extended rights
                                        if (accessrule.ObjectFlags == ObjectAceFlags.None
                                            && (accessrule.ActiveDirectoryRights & ActiveDirectoryRights.ExtendedRight) == ActiveDirectoryRights.ExtendedRight)
                                        {
                                            f = true;
                                            break;
                                        }
                                    }
                                }
                                if (f)
                                {
                                    healthcheckData.ListLAPSJoinedComputersToReview.Add(GetAccountDetail(x));
                                }
                            }
                        }
                    }
                    );
            }
            return lapsAnalyzer;
        }

        private void CheckAdminSDHolderNotOK(ADDomainInfo domainInfo, ADWebService adws)
        {
            List<string> privilegedUser = new List<string>();
            foreach (var member in healthcheckData.AllPrivilegedMembers)
            {
                privilegedUser.Add(member.DistinguishedName);
            }
            if (healthcheckData.ProtectedUsersNotPrivileged != null && healthcheckData.ProtectedUsersNotPrivileged.Members != null)
            {
                foreach (var member in healthcheckData.ProtectedUsersNotPrivileged.Members)
                {
                    privilegedUser.Add(member.DistinguishedName);
                }
            }

            healthcheckData.AdminSDHolderNotOK = new List<HealthcheckAccountDetailData>();

            WorkOnReturnedObjectByADWS callbackAdminSDHolder =
                (ADItem x) =>
                {
                    if (!privilegedUser.Contains(x.DistinguishedName))
                    {
                        // ignore honey pot accounts
                        if (healthcheckData.ListHoneyPot != null)
                        {
                            foreach (var u in healthcheckData.ListHoneyPot)
                            {
                                if (string.Equals(u.Name, x.SAMAccountName, StringComparison.InvariantCultureIgnoreCase))
                                    return;
                                if (string.Equals(u.DistinguishedName, x.DistinguishedName, StringComparison.InvariantCultureIgnoreCase))
                                    return;
                            }
                        }
                        var w = GetAccountDetail(x);
                        if (x.ReplPropertyMetaData != null && x.ReplPropertyMetaData.ContainsKey(589974))
                        {
                            w.Event = x.ReplPropertyMetaData[589974].LastOriginatingChange;
                        }
                        healthcheckData.AdminSDHolderNotOK.Add(w);
                    }
                };
            
            var filter = "(&(objectClass=user)(objectCategory=person)(admincount=1)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(sAMAccountName=krbtgt)))";
            adws.Enumerate(domainInfo.DefaultNamingContext, filter, CommonAccountProperties, callbackAdminSDHolder);
            healthcheckData.AdminSDHolderNotOKCount = healthcheckData.AdminSDHolderNotOK.Count;
        }

        private void CheckSmartCard(ADDomainInfo domainInfo, ADWebService adws)
        {
            if (healthcheckData.DomainFunctionalLevel < 3)
                return;

            // enumerates the account with the flag "smart card required" and not disabled
            healthcheckData.SmartCardNotOK = new List<HealthcheckAccountDetailData>();
            WorkOnReturnedObjectByADWS callbackSmartCard =
                (ADItem x) =>
                {
                    // apply a filter on the last nt hash change (attribute unicodePwd) via replication metadata
                    if (x.ReplPropertyMetaData != null && x.ReplPropertyMetaData.ContainsKey(589914)
                        && x.ReplPropertyMetaData[589914].LastOriginatingChange.AddDays(91) < DateTime.Now)
                    {
                        healthcheckData.SmartCardNotOK.Add(GetAccountDetail(x));
                    }
                };

            var filter = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(userAccountControl:1.2.840.113556.1.4.803:=262144))";
            adws.Enumerate(domainInfo.DefaultNamingContext, filter, CommonAccountProperties, callbackSmartCard);
            healthcheckData.SmartCardNotOKCount = healthcheckData.SmartCardNotOK.Count;
        }

        private void CheckPreWindows2000Group(ADDomainInfo domainInfo, ADWebService adws)
        {
            string[] PreWin2000properties = new string[] {
                        "distinguishedName",
                        "member",
            };

            healthcheckData.PreWindows2000Members = new List<string>();

            WorkOnReturnedObjectByADWS callbackPreWin2000 =
                (ADItem x) =>
                {
                    if (x.Member != null)
                    {
                        foreach (string member in x.Member)
                        {
                            // anonymous then eveyone
                            if (member.Contains("S-1-5-7") || member.Contains("S-1-1-0"))
                            {
                                healthcheckData.PreWindows2000AnonymousAccess = true;
                                continue;
                            }
                            if (member.Contains("S-1-5-11"))
                            {
                                healthcheckData.PreWindows2000AuthenticatedUsers = true;
                            }
                            if (!member.StartsWith("CN=S-"))
                            {
                                healthcheckData.PreWindows2000NoDefault = true;
                                healthcheckData.PreWindows2000Members.Add(member);
                                continue;
                            }
                        }
                    }
                };
            adws.Enumerate(domainInfo.DefaultNamingContext, "(objectSid=" + ADConnection.EncodeSidToString("S-1-5-32-554") + ")", PreWin2000properties, callbackPreWin2000);
        }

        private void CheckDsHeuristics(ADDomainInfo domainInfo, ADWebService adws)
        {
            string[] DsHeuristicsproperties = new string[] {
                        "distinguishedName",
                        "dSHeuristics",
                        "msDS-Other-Settings",
            };
            WorkOnReturnedObjectByADWS callbackdSHeuristics =
                (ADItem x) =>
                {
                    if (!String.IsNullOrEmpty(x.DSHeuristics))
                    {
                        healthcheckData.DSHeuristics = x.DSHeuristics;
                    }
                    if (x.msDSOtherSettings != null)
                    {
                        healthcheckData.DSOtherSettings = new List<string>(x.msDSOtherSettings);
                    }
                };
            adws.Enumerate(domainInfo.ConfigurationNamingContext, "(distinguishedName=CN=Directory Service,CN=Windows NT,CN=Services," + domainInfo.ConfigurationNamingContext + ")", DsHeuristicsproperties, callbackdSHeuristics);
        }

        private void CheckRootDomainProperties(ADDomainInfo domainInfo, ADWebService adws)
        {
            WorkOnReturnedObjectByADWS callbackDSQuota =
                (ADItem x) =>
                {
                    healthcheckData.MachineAccountQuota = x.DSMachineAccountQuota;
                    healthcheckData.ExpirePasswordsOnSmartCardOnlyAccounts = x.msDSExpirePasswordsOnSmartCardOnlyAccounts;
                };
            var properties = new List<string> {
                "ms-DS-MachineAccountQuota",
            };
            // starting Win 2016
            if (healthcheckData.DomainFunctionalLevel >= 7)
                properties.Add("msDS-ExpirePasswordsOnSmartCardOnlyAccounts");

            adws.Enumerate(domainInfo.DefaultNamingContext, "(&(objectClass=domain)(distinguishedName=" + domainInfo.DefaultNamingContext + "))", properties.ToArray(), callbackDSQuota, "Base");
        }

        private void CheckSIDHistoryAuditingGroupPresent(ADDomainInfo domainInfo, ADWebService adws)
        {
            string[] SIDHistoryproperties = new string[] {
                "sAMAccountName",
            };
            WorkOnReturnedObjectByADWS callbackSIDHistory =
                (ADItem x) =>
                {
                    healthcheckData.SIDHistoryAuditingGroupPresent = true;
                };
            adws.Enumerate(domainInfo.DefaultNamingContext, "(sAMAccountName=" + domainInfo.NetBIOSName + "$$$)", SIDHistoryproperties, callbackSIDHistory);
        }

        private void CheckDCOwners(ADDomainInfo domainInfo, ADWebService adws)
        {
            WorkOnReturnedObjectByADWS callbackDomainControllers =
                            (ADItem x) =>
                            {
                                foreach (var DC in healthcheckData.DomainControllers)
                                {
                                    if (String.Equals(DC.DistinguishedName, x.DistinguishedName, StringComparison.InvariantCultureIgnoreCase))
                                    {
                                        if (x.NTSecurityDescriptor == null)
                                            return;
                                        DC.OwnerSID = x.NTSecurityDescriptor.GetOwner(typeof(SecurityIdentifier)).Value;
                                        DC.OwnerName = adws.ConvertSIDToName(DC.OwnerSID);
                                        return;
                                    }
                                }
                            };
            string[] DCProperties = new string[] {
                "distinguishedName",
                "nTSecurityDescriptor",
            };
            foreach (var DC in healthcheckData.DomainControllers)
            {
                adws.Enumerate(domainInfo.DefaultNamingContext, "(distinguishedName=" + ADConnection.EscapeLDAP(DC.DistinguishedName) + ")", DCProperties, callbackDomainControllers);
            }
        }

        private void CheckPrivExchange(ADDomainInfo domainInfo, ADWebService adws)
        {
            string[] ExchangePrivEscProperties = new string[] {
                "distinguishedName",
                "nTSecurityDescriptor",
            };
            WorkOnReturnedObjectByADWS callbackExchangePrivEscProperties =
                (ADItem x) =>
                {
                    if (x.NTSecurityDescriptor != null)
                    {
                        foreach (ActiveDirectoryAccessRule rule in x.NTSecurityDescriptor.GetAccessRules(true, false, typeof(SecurityIdentifier)))
                        {
                            if (((rule.ActiveDirectoryRights & ActiveDirectoryRights.WriteDacl) != 0)
                                && (rule.ObjectType == new Guid("00000000-0000-0000-0000-000000000000"))
                                && rule.PropagationFlags == PropagationFlags.None)
                            {
                                string principal = adws.ConvertSIDToName(rule.IdentityReference.Value);
                                if (principal.EndsWith("\\Exchange Windows Permissions"))
                                {

                                    healthcheckData.ExchangePrivEscVulnerable = true;
                                }
                            }
                        }
                    }
                };
            adws.Enumerate(domainInfo.DefaultNamingContext, "(objectClass=*)", ExchangePrivEscProperties, callbackExchangePrivEscProperties, "Base");
        }

        private void CheckSchemaVulnerable(ADDomainInfo domainInfo, ADWebService adws)
        {
            string[] MSRC65221Properties = new string[] {
                "distinguishedName",
                "possSuperiors",
                "lDAPDisplayName",
                "subClassOf",
            };
            // see https://bugs.chromium.org/p/project-zero/issues/detail?id=2186
            // https://gist.github.com/IISResetMe/399a75cfccabc1a17d0cc3b5ae29f3aa#file-update-msexchstoragegroupschema-ps1
            var allSchema = new Dictionary<string, ADItem>();
            var schemaToCheck = new List<string>();
            WorkOnReturnedObjectByADWS callbackMSRC65221 =
                (ADItem x) =>
                {
                    try
                    {
                        allSchema.Add(x.lDAPDisplayName, x);
                    }
                    catch (ArgumentException)
                    {
                        DisplayAdvancementWarning("Warning: Duplicate lDAPDisplayName detected in schema: " + x.lDAPDisplayName + " (" + x.DistinguishedName + " and " + allSchema[x.lDAPDisplayName].DistinguishedName + ")");
                    }
                    if (x.possSuperiors != null)
                    {
                        var poss = new List<string>(x.possSuperiors);
                        if (poss.Contains("computer") || poss.Contains("user"))
                        {
                            schemaToCheck.Add(x.lDAPDisplayName);
                        }
                    }
                };
            adws.Enumerate(domainInfo.SchemaNamingContext, "(objectclass=classSchema)", MSRC65221Properties, callbackMSRC65221, "OneLevel");
            foreach (var classToCheck in schemaToCheck)
            {
                string next = allSchema[classToCheck].subClassOf;
                int depth = 100;
                while (next != "top" && next != "container" && depth-- > 0)
                {
                    next = allSchema[next].subClassOf;
                }
                if (next == "container")
                {
                    if (healthcheckData.SchemaClassVulnerable == null)
                        healthcheckData.SchemaClassVulnerable = new List<HealthcheckSchemaClassVulnerable>();
                    var poss = new List<string>(allSchema[classToCheck].possSuperiors);
                    var vuln = new HealthcheckSchemaClassVulnerable();
                    vuln.Class = classToCheck;
                    if (poss.Contains("computer"))
                    {
                        vuln.Vulnerability = "PossSuperiorComputer";
                    }
                    if (poss.Contains("user"))
                    {
                        vuln.Vulnerability = "PossSuperiorUser";
                    }
                    healthcheckData.SchemaClassVulnerable.Add(vuln);
                }
            }
        }

        private void CheckUnixPassword(ADDomainInfo domainInfo, ADWebService adws)
        {
            healthcheckData.UnixPasswordUsers = new List<HealthcheckAccountDetailData>();

            WorkOnReturnedObjectByADWS callbackUnixPassword =
                (ADItem x) =>
                {
                    var w = GetAccountDetail(x);
                    healthcheckData.UnixPasswordUsers.Add(w);

                    if (x.ReplPropertyMetaData == null)
                        return;
                    if (x.ReplPropertyMetaData.ContainsKey(35)) // userPassword
                    {
                        w.Event = x.ReplPropertyMetaData[35].LastOriginatingChange;
                    }
                    if (x.ReplPropertyMetaData.ContainsKey(591734)) // unixUserPassword
                    {
                        w.Event = x.ReplPropertyMetaData[591734].LastOriginatingChange;
                    }
                };

            var filter = "(&(objectCategory=person)(!userAccountControl:1.2.840.113556.1.4.803:=2)(|(unixUserPassword=*)(userPassword=*)))";
            adws.Enumerate(domainInfo.DefaultNamingContext, filter, CommonAccountProperties, callbackUnixPassword);
            healthcheckData.UnixPasswordUsersCount = healthcheckData.UnixPasswordUsers.Count;
        }

        private void CheckLDAPIpDenyList(ADDomainInfo domainInfo, ADWebService adws)
        {
            // adding the ldap denyip
            string[] propertiesLDAPDenyIP = new string[] {
                        "distinguishedName",
                        "lDAPIPDenyList",
            };

            healthcheckData.lDAPIPDenyList = new List<string>();
            WorkOnReturnedObjectByADWS callbackLDAPDenyIP =
                (ADItem x) =>
                {
                    Trace.WriteLine("lDAPIPDenyList found in ");
                    Trace.WriteLine(x.DistinguishedName);
                    foreach (var ip in x.lDAPIPDenyList)
                    {
                        var i = Encoding.UTF8.GetString(ip).Trim();
                        if (Regex.Match(i, "^(?:[0-9]{1,3}\\.){3}[0-9]{1,3} (?:[0-9]{1,3}\\.){3}[0-9]{1,3}$").Success)
                        {
                            healthcheckData.lDAPIPDenyList.Add(i);
                        }
                    }
                };
            adws.Enumerate(domainInfo.ConfigurationNamingContext, "(&(objectclass=queryPolicy)(lDAPIPDenyList=*))", propertiesLDAPDenyIP, callbackLDAPDenyIP);
        }

        private void CheckJavaTrustedData(ADDomainInfo domainInfo, ADWebService adws)
        {
            string[] propertiesJava = new string[] {
                        "distinguishedName",
                        "lDAPDisplayName",
            };
            healthcheckData.JavaClassFound = false;
            WorkOnReturnedObjectByADWS callbackJava =
                (ADItem x) =>
                {
                    Trace.WriteLine("lDAPDisplayName java attribute found in ");
                    Trace.WriteLine(x.DistinguishedName);
                    switch (x.lDAPDisplayName.ToLowerInvariant())
                    {
                        case "javacodebase":
                        case "javafactory":
                        case "javaclassname":
                        case "javaserializeddata":
                        case "javaremotelocation":
                            healthcheckData.JavaClassFound = true;
                            break;
                    }

                };
            adws.Enumerate(domainInfo.SchemaNamingContext, "(&(objectClass=attributeschema)(lDAPDisplayName=java*))", propertiesJava, callbackJava, "OneLevel");

            if (healthcheckData.JavaClassFound)
            {
                healthcheckData.JavaClassFoundDetail = new List<HealthcheckAccountDetailData>();
                
                WorkOnReturnedObjectByADWS callbackJavaUser =
                (ADItem x) =>
                {
                    var w = GetAccountDetail(x);
                    healthcheckData.JavaClassFoundDetail.Add(w);
                };
                var filter = "(&(objectCategory=person)(!userAccountControl:1.2.840.113556.1.4.803:=2)(|((javacodebase=*)(javafactory=*)(javaclassname=*)(javaserializeddata=*)(javaremotelocation=*))))";
                adws.Enumerate(domainInfo.DefaultNamingContext, filter, CommonAccountProperties, callbackJavaUser);
            }
        }

        private void CheckServicePointData(ADDomainInfo domainInfo, ADWebService adws)
        {
            healthcheckData.ServicePoints = new List<HealthCheckServicePoint>();
            string[] properties = new string[] {
                        "distinguishedName",
                        "serviceClassName",
                        "serviceDNSName",
                        "serviceBindingInformation",
                        "whenCreated",
                };
            WorkOnReturnedObjectByADWS callback =
            (ADItem x) =>
            {
                var s = new HealthCheckServicePoint();
                s.DN = x.DistinguishedName;
                s.ClassName = x.ServiceClassName;
                s.DNS = x.ServiceDNSName;
                if (x.ServiceBindingInformation != null)
                    s.BindingInfo = new List<string>(x.ServiceBindingInformation);
                healthcheckData.ServicePoints.Add(s);
            };
            string filter = "(&(objectCategory=ServiceConnectionPoint)(serviceClassName=*))";
            adws.Enumerate(domainInfo.DefaultNamingContext, filter, properties, callback);
            adws.Enumerate(domainInfo.ConfigurationNamingContext, filter, properties, callback);
        }


        private void CheckDisplaySpecifier(ADDomainInfo domainInfo, ADWebService adws)
        {
            healthcheckData.DisplaySpecifier = new List<HealthCheckDisplaySpecifier>();
            string[] properties = new string[] {
                        "distinguishedName",
                        "adminContextMenu",
                        "whenChanged",
                };
            WorkOnReturnedObjectByADWS callback =
            (ADItem x) =>
            {
                if (x.AdminContextMenu != null)
                {
                    foreach (var entry in x.AdminContextMenu)
                    {
                        if (string.IsNullOrEmpty(entry))
                            continue;
                        var e = entry.Split(',');
                        if (e.Length < 3)
                            continue;
                        var path = e[2];
                        if (!path.Contains("\\\\"))
                            continue;
                        healthcheckData.DisplaySpecifier.Add(new HealthCheckDisplaySpecifier
                        {
                            DN = x.DistinguishedName,
                            AdminContextMenu = entry,
                            WhenChanged = x.WhenChanged,
                        });
                    }
                }
            };
            adws.Enumerate("CN=DisplaySpecifiers," + domainInfo.ConfigurationNamingContext, "(objectCategory=displaySpecifier)", properties, callback);
        }

        private void GenerateDomainControllerData(ADDomainInfo domainInfo, ADWebService adws, PingCastleAnalyzerParameters parameters)
        {
            Trace.WriteLine("GenerateDomainControllerData");
            BlockingQueue<HealthcheckDomainController> queue = new BlockingQueue<HealthcheckDomainController>(200);
            int numberOfThread = 50;
            Thread[] threads = new Thread[numberOfThread];
            try
            {

                ParameterizedThreadStart threadFunction = (object index) =>
                {
                    adws.ThreadInitialization();
                    int threadId = (int)index;
                    for (; ; )
                    {
                        HealthcheckDomainController DC = null;
                        if (!queue.Dequeue(out DC))
                        {
                            Trace.WriteLine("[" + threadId + "] Thread Stop");
                            break;
                        }
                        string dns = DC.DCName + "." + domainInfo.DomainName;
                        Trace.WriteLine("[" + threadId + "] Working on " + dns);
                        DC.IP = new List<string>();
                        IPAddress[] addresses = null;
                        try
                        {
                            addresses = Dns.GetHostEntry(dns).AddressList;
                        }
                        catch (Exception)
                        {
                            Trace.WriteLine("[" + threadId + "] Unable to resolve DC " + dns);
                            continue;
                        }
                        foreach (var address in addresses)
                        {
                            string addressString = address.ToString();
                            switch (addressString)
                            {
                                // avoid registering the loopback address
                                case "::1":
                                case "127.0.0.1":
                                    break;
                                default:
                                    DC.IP.Add(addressString);
                                    break;
                            }
                        }
                        Trace.WriteLine("[" + threadId + "] Getting individual LDAP data" + dns);
                        try
                        {
                            var localAdws = new LDAPConnection(dns, parameters.Port, parameters.Credential);

                            var localDomainInfo = localAdws.GetDomainInfo();
                            Trace.WriteLine("[" + threadId + "] Connected LDAP to " + localDomainInfo.DnsHostName);

                            string[] adminProperties = new string[] {
                            "distinguishedName",
                            "lastlogon",
                            };
                            WorkOnReturnedObjectByADWS callback =
                                    (ADItem x) =>
                                    {
                                        DC.AdminLocalLogin = x.LastLogon;
                                    };
                            localAdws.Enumerate(domainInfo.DefaultNamingContext, "(objectSid=" + ADConnection.EncodeSidToString(domainInfo.DomainSid + "-" + 500) + ")", adminProperties, callback, "SubTree");
                        }
                        catch (Exception ex)
                        {
                            Trace.WriteLine("[" + threadId + "] Exception while getting admin login time: " + ex.Message);
                            Trace.WriteLine("[" + threadId + "] " + ex.StackTrace);
                        }

                        Trace.WriteLine("[" + threadId + "] Working on startup " + dns);
                        DC.StartupTime = NativeMethods.GetStartupTime(dns);
                        if (DC.StartupTime == DateTime.MinValue)
                        {
                            // startup time could not be obtained - consider the DC as down
                        }
                        if (!SkipNullSession)
                        {
                            Trace.WriteLine("[" + threadId + "] Working on null session " + dns);
                            NullSessionTester session = new NullSessionTester(dns);
                            if (session.EnumerateAccount(1))
                            {
                                DC.HasNullSession = true;
                            }
                        }
                        Trace.WriteLine("[" + threadId + "] Working on smb support " + dns);
                        SMBSecurityModeEnum securityMode;
                        if (SmbScanner.SupportSMB1(dns, out securityMode, "[" + threadId + "] "))
                        {
                            DC.SupportSMB1 = true;
                        }
                        DC.SMB1SecurityMode = securityMode;
                        if (SmbScanner.SupportSMB2And3(dns, out securityMode, "[" + threadId + "] "))
                        {
                            DC.SupportSMB2OrSMB3 = true;
                        }
                        DC.SMB2SecurityMode = securityMode;
                        if (!SkipNullSession)
                        {
                            Trace.WriteLine("[" + threadId + "] Working on spooler " + dns);
                            DC.RemoteSpoolerDetected = SpoolerScanner.CheckIfTheSpoolerIsActive(dns);
                        }
                        if (DC.SMB1SecurityMode != SMBSecurityModeEnum.NotTested && DC.SMB2SecurityMode != SMBSecurityModeEnum.NotTested)
                        {
                            if (NamedPipeTester.IsRemotePipeAccessible(dns, NamedPipeTester.WebClientPipeName, "[" + threadId + "] "))
                            {
                                DC.WebClientEnabled = true;
                            }
                        }
                        Trace.WriteLine("[" + threadId + "] Working on ldap ssl " + dns);
                        GenerateTLSConnectionInfo(dns, DC, adws.Credential, threadId);
                        Trace.WriteLine("[" + threadId + "] Working on ldap signing requirements " + dns);
                        GenerateLDAPSigningRequirementInfo(dns, DC, adws.Credential, threadId);
                        if (!SkipRPC)
                        {
                            Trace.WriteLine("[" + threadId + "] testing RPC " + dns);
                            TestFirewallRPCDC(DC, threadId);
                        }
                        Trace.WriteLine("[" + threadId + "] Done for " + dns);
                    }
                };

                // Consumers
                for (int i = 0; i < numberOfThread; i++)
                {
                    threads[i] = new Thread(threadFunction);
                    threads[i].Start(i);
                }

                foreach (HealthcheckDomainController DC in healthcheckData.DomainControllers)
                {
                    queue.Enqueue(DC);
                }
                queue.Quit();
                Trace.WriteLine("examining dc completed. Waiting for worker thread to complete");
                for (int i = 0; i < numberOfThread; i++)
                {
                    Trace.WriteLine("Waiting for Thead " + i);
                    threads[i].Join();
                    Trace.WriteLine("Waiting for Thead " + i + " => Done");
                }
                Trace.WriteLine("Done testing null session");
            }
            catch (Exception ex)
            {
                Trace.WriteLine("Exception while generating null session Data: " + ex.Message);
                Trace.WriteLine(ex.StackTrace);
                lock (this)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Exception while generating null session Data: " + ex.Message);
                    Console.WriteLine(ex.StackTrace);
                    Console.ResetColor();
                }
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
            foreach (var DC in healthcheckData.DomainControllers)
            {
                if (DC.HasNullSession)
                    healthcheckData.DomainControllerWithNullSessionCount++;
            }
        }

        class RPCTest
        {
            public Guid guid;
            public string pipe;
            public ushort major;
            public ushort minor;
            public Dictionary<string, int> functions;
        }

        void TestFirewallRPCDC(HealthcheckDomainController DC, int threadId)
        {
            var toTest = new List<RPCTest>
            {
                new RPCTest {
                    guid = Guid.Parse("4fc742e0-4a10-11cf-8273-00aa004ae673"),
                    pipe = "netdfs",
                    major = 3,
                    functions = new Dictionary<string, int> { { "NetrDfsAddStdRoot", 12 }, { "NetrDfsRemoveStdRoot", 13 } }
                },
                new RPCTest {
                    guid = Guid.Parse("82273fdc-e32a-18c3-3f78-827929dc23ea"),
                    pipe = "eventlog",
                    functions =    new Dictionary<string, int> { { "ElfrOpenBELW", 9 }}
                },
                new RPCTest {
                    guid = Guid.Parse("c681d488-d850-11d0-8c52-00c04fd90f7e"),
                    pipe = "efsrpc",
                    major = 1,
                    functions = new Dictionary<string, int> { { "EfsRpcAddUsersToFile", 9 }, { "EfsRpcAddUsersToFileEx", 15 },
                                                            {"EfsRpcDecryptFileSrv", 5}, {"EfsRpcDuplicateEncryptionInfoFile",12},
                                                            {"EfsRpcEncryptFileSrv",4 },{"EfsRpcFileKeyInfo",12 },
                                                            {"EfsRpcOpenFileRaw",0 },{"EfsRpcQueryRecoveryAgents",7 },
                                                            {"EfsRpcQueryUsersOnFile", 6}, {"EfsRpcRemoveUsersFromFile", 8},
                    },
                },
                new RPCTest {
                    guid = Guid.Parse("a8e0653c-2744-4389-a61d-7373df8b2292"),
                    pipe = "Fssagentrpc",
                    major = 1,
                    functions =    new Dictionary<string, int> { { "IsPathShadowCopied", 9 },{ "IsPathSupported", 8 }}
                },
                new RPCTest {
                    guid = Guid.Parse("12345678-1234-ABCD-EF00-0123456789AB"),
                    pipe = "spoolss",
                    major = 1,
                    minor = 0,
                    functions = new Dictionary<string, int> { { "RpcRemoteFindFirstPrinterChangeNotification", 62 },{ "RpcRemoteFindFirstPrinterChangeNotificationEx", 65 }}
                },
            };

            DC.RPCInterfacesOpen = new List<HealthcheckDCRPCInterface>();

            if (IsDCTheLocalComputer(DC))
            {
                Trace.WriteLine("[" + threadId + "] RPC test stopped for " + DC.DCName + " because this is the local computer");
                return;
            }

            foreach (var ip in DC.IP)
            {
                Trace.WriteLine("[" + threadId + "] testing IP " + ip);
                foreach (var test in toTest)
                {
                    Trace.WriteLine("[" + threadId + "] testing RPC interface " + test.guid);
                    foreach (var r in RpcFirewallChecker.TestFunctions(ip, test.guid, test.pipe, test.major, test.minor, test.functions))
                    {
                        Trace.WriteLine("[" + threadId + "] found " + r + " available");

                        DC.RPCInterfacesOpen.Add(new HealthcheckDCRPCInterface
                        {
                            IP = ip,
                            Function = r,
                            Interface = test.guid.ToString(),
                            OpNum = test.functions[r],
                        });
                    }
                }
            }
        }

        bool IsDCTheLocalComputer(HealthcheckDomainController dc)
        {
            NetworkInterface[] networkInterfaces = NetworkInterface.GetAllNetworkInterfaces();
            foreach (NetworkInterface nic in networkInterfaces)
            {
                if (nic.OperationalStatus == OperationalStatus.Up)
                {
                    IPInterfaceProperties ipProperties = nic.GetIPProperties();
                    foreach (UnicastIPAddressInformation ipInfo in ipProperties.UnicastAddresses)
                    {
                        if (ipInfo.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        {
                            foreach (var ip in dc.IP)
                            {
                                if (ip == ipInfo.Address.ToString())
                                {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
            return false;
        }

        private void GenerateTLSConnectionInfo(string dns, HealthcheckDomainController DC, NetworkCredential credentials, int threadId)
        {
            DC.LDAPSProtocols = new List<string>();
            byte[] certificate;
            Trace.WriteLine("[" + threadId + "] GenerateTLSInfo");
            GenerateTLSInfo(dns, 636, DC.LDAPSProtocols, out certificate, "[" + threadId + "] ");
            DC.LDAPCertificate = certificate;
            if (DC.LDAPSProtocols.Count > 0)
            {
                if (DoesComputerMatchDns(dns))
                {
                    Trace.WriteLine("[" + threadId + "] Test ignored because tested on the DC itself");
                    return;
                }
                Trace.WriteLine("[" + threadId + "] TestExtendedAuthentication");
                var result = ConnectionTester.TestExtendedAuthentication(new Uri("ldaps://" + dns), credentials, "[" + threadId + "] ");
                Trace.WriteLine("[" + threadId + "] Result:" + result);
                if (result == ConnectionTesterStatus.ChannelBindingDisabled)
                {
                    DC.ChannelBindingDisabled = true;
                }
            }
        }

        private void GenerateLDAPSigningRequirementInfo(string dns, HealthcheckDomainController DC, NetworkCredential credentials, int threadId)
        {
            if (DoesComputerMatchDns(dns))
            {
                Trace.WriteLine("[" + threadId + "] Test ignored because tested on the DC itself");
                return;
            }
            Trace.WriteLine("[" + threadId + "] TestSignatureRequiredEnabled");
            var result = ConnectionTester.TestSignatureRequiredEnabled(new Uri("ldap://" + dns), credentials, "[" + threadId + "] ");
            Trace.WriteLine("[" + threadId + "] Result:" + result);
            if (result == ConnectionTesterStatus.SignatureNotRequired)
            {
                DC.LdapServerSigningRequirementDisabled = true;
            }
        }

        bool DoesComputerMatchDns(string Dns)
        {
            string hostName = System.Net.Dns.GetHostEntry("LocalHost").HostName;
            return string.Equals(hostName, Dns, StringComparison.OrdinalIgnoreCase);
        }

        private void GenerateTLSInfo(string dns, int port, List<string> protocols, out byte[] certificate, string logPrefix)
        {
            certificate = null;
            foreach (SslProtocols protocol in Enum.GetValues(typeof(SslProtocols)))
            {
                if (protocol == SslProtocols.Default)
                    continue;
                if (protocol == SslProtocols.None)
                    continue;
                try
                {
                    byte[] c = null;
                    using (TcpClient client = new TcpClient(dns, port))
                    {
                        client.ReceiveTimeout = 1000;
                        client.SendTimeout = 1000;
                        using (SslStream sslstream = new SslStream(client.GetStream(), false,
                                (object sender, X509Certificate CACert, X509Chain CAChain, SslPolicyErrors sslPolicyErrors)
                                    =>
                                { c = CACert.GetRawCertData(); return true; }
                                     , null))
                        {
                            Trace.WriteLine(logPrefix + protocol + " before auth for " + dns);
                            sslstream.AuthenticateAsClient(dns, null, protocol, false);
                            Trace.WriteLine(logPrefix + protocol + " supported for " + dns);
                            certificate = c;
                            protocols.Add(protocol.ToString());
                        }
                    }
                }
                catch (SocketException)
                {
                    Trace.WriteLine(logPrefix + "SSL not supported for " + dns);
                    return;
                }
                catch (Exception ex)
                {
                    Trace.WriteLine(logPrefix + protocol + " not supported for " + dns + ":" + port + " (" + ex.Message + (ex.InnerException == null ? null : " - " + ex.InnerException.Message) + ")");
                }
            }
        }

        // a site can have more than 1500 subnet, which is the limit for properties retrieval
        private void GenerateNetworkData(ADDomainInfo domainInfo, ADWebService adws)
        {
            string[] properties = new string[] {
                        "distinguishedName",
                        "name",
                        "description",
                        "location",
            };
            var sites = new Dictionary<string, HealthcheckSite>();
            WorkOnReturnedObjectByADWS callback =
                (ADItem x) =>
                {
                    var site = new HealthcheckSite();
                    site.SiteName = x.Name;
                    site.Description = x.Description;
                    site.Location = x.Location;
                    site.Networks = new List<string>();

                    sites.Add(x.DistinguishedName, site);
                };

            adws.Enumerate(domainInfo.ConfigurationNamingContext, "(objectClass=site)", properties, callback);

            string[] subnetproperties = new string[] {
                        "distinguishedName",
                        "name",
                        "siteObject",
            };

            WorkOnReturnedObjectByADWS callbacksubnet =
                (ADItem x) =>
                {
                    if (!string.IsNullOrEmpty(x.SiteObject))
                    {
                        if (sites.ContainsKey(x.SiteObject) && !string.IsNullOrEmpty(x.Name))
                        {
                            sites[x.SiteObject].Networks.Add(x.Name);
                        }
                    }
                };

            adws.Enumerate(domainInfo.ConfigurationNamingContext, "(objectClass=subnet)", subnetproperties, callbacksubnet);

            healthcheckData.Sites = new List<HealthcheckSite>();
            foreach (var site in sites.Values)
            {
                healthcheckData.Sites.Add(site);
            }
        }

        private void GenerateRODCData(ADDomainInfo domainInfo, ADWebService adws)
        {

            string[] properties = new string[] { "distinguishedName", "member" };

            healthcheckData.DeniedRODCPasswordReplicationGroup = new List<string>();
            var members = new List<string>();
            adws.Enumerate(domainInfo.DefaultNamingContext, "(objectSid=" + ADConnection.EncodeSidToString(domainInfo.DomainSid.Value + "-572") + ")", properties,
                (ADItem aditem) =>
                {
                    Trace.WriteLine("CN=Denied RODC Password Replication Group found");
                    if (aditem.Member != null)
                    {
                        foreach (var member in aditem.Member)
                        {
                            members.Add(member);
                        }
                    }
                }
            );

            string[] properties2 = new string[] { "objectSid" };
            foreach (var member in members)
            {
                bool found = false;
                adws.Enumerate(domainInfo.DefaultNamingContext,
                                            "(distinguishedName=" + member + ")",
                                            properties2,
                                            (ADItem aditem) =>
                                            {
                                                found = true;
                                                healthcheckData.DeniedRODCPasswordReplicationGroup.Add(aditem.ObjectSid.Value);
                                            }
                                            );
                if (!found)
                {
                    healthcheckData.DeniedRODCPasswordReplicationGroup.Add(member);
                }
            }

            healthcheckData.AllowedRODCPasswordReplicationGroup = new List<string>();
            adws.Enumerate(domainInfo.DefaultNamingContext, "(objectSid=" + ADConnection.EncodeSidToString(domainInfo.DomainSid.Value + "-571") + ")", properties,
                (ADItem aditem) =>
                {
                    Trace.WriteLine("CN=Allowed RODC Password Replication Group found");
                    if (aditem.Member != null)
                    {
                        foreach (var member in aditem.Member)
                        {
                            healthcheckData.AllowedRODCPasswordReplicationGroup.Add(member);
                        }
                    }
                }
            );


            var msDSRevealOnDemandGroup = new Dictionary<string, List<string>>();
            var msDSNeverRevealGroup = new Dictionary<string, List<string>>();

            var sidResolution = new Dictionary<string, string>();

            adws.Enumerate(domainInfo.DefaultNamingContext, "(primaryGroupID=521)", new string[] { "distinguishedName", "msDS-RevealedUsers", "msDS-RevealOnDemandGroup", "msDS-NeverRevealGroup" },
                (ADItem aditem) =>
                {
                    HealthcheckDomainController dc = null;
                    foreach (var d in healthcheckData.DomainControllers)
                    {
                        if (d.DistinguishedName == aditem.DistinguishedName)
                        {
                            dc = d;
                            break;
                        }
                    }
                    if (dc == null)
                        return;
                    dc.RODC = true;

                    dc.msDSRevealedUsers = new List<string>();
                    if (aditem.msDSRevealedUsers != null)
                    {
                        foreach (var u in aditem.msDSRevealedUsers)
                        {
                            var i = u.IndexOf(':');
                            var j = u.IndexOf(':', i + 1);
                            var k = u.IndexOf(':', j + 1);
                            var v = u.Substring(k + 1);
                            if (!dc.msDSRevealedUsers.Contains(v))
                                dc.msDSRevealedUsers.Add(v);
                        }
                    }
                    if (aditem.msDSRevealOnDemandGroup != null)
                        msDSRevealOnDemandGroup[aditem.DistinguishedName] = new List<string>(aditem.msDSRevealOnDemandGroup);
                    if (aditem.msDSNeverRevealGroup != null)
                        msDSNeverRevealGroup[aditem.DistinguishedName] = new List<string>(aditem.msDSNeverRevealGroup);
                }
            );
            if (msDSRevealOnDemandGroup != null)
            {
                foreach (var v in msDSRevealOnDemandGroup.Values)
                    foreach (var w in v)
                    {
                        if (!sidResolution.ContainsKey(w))
                            sidResolution[w] = w;
                    }
            }
            if (msDSNeverRevealGroup != null)
            {
                foreach (var v in msDSNeverRevealGroup.Values)
                    foreach (var w in v)
                    {
                        if (!sidResolution.ContainsKey(w))
                            sidResolution[w] = w;
                    }
            }
            foreach (var dn in new List<string>(sidResolution.Keys))
            {
                adws.Enumerate(domainInfo.DefaultNamingContext,
                                            "(distinguishedName=" + dn + ")",
                                            properties2,
                                            (ADItem aditem) =>
                                            {
                                                if (aditem.ObjectSid != null)
                                                {
                                                    sidResolution[dn] = aditem.ObjectSid.Value;
                                                }
                                            }
                                            );
            }
            foreach (var dc in healthcheckData.DomainControllers)
            {
                if (msDSRevealOnDemandGroup.ContainsKey(dc.DistinguishedName))
                {
                    dc.msDSRevealOnDemandGroup = new List<string>();
                    foreach (var u in msDSRevealOnDemandGroup[dc.DistinguishedName])
                    {
                        if (sidResolution.ContainsKey(u))
                            dc.msDSRevealOnDemandGroup.Add(sidResolution[u]);
                    }
                }
                if (msDSNeverRevealGroup != null && msDSNeverRevealGroup.ContainsKey(dc.DistinguishedName))
                {
                    dc.msDSNeverRevealGroup = new List<string>();
                    foreach (var u in msDSNeverRevealGroup[dc.DistinguishedName])
                    {
                        if (sidResolution.ContainsKey(u))
                            dc.msDSNeverRevealGroup.Add(sidResolution[u]);
                    }
                }
            }


            //Search for RODC without Readonly flag on sysvol
            adws.Enumerate(domainInfo.DefaultNamingContext,
                                            "(&(msDFSR-ReadOnly=FALSE)(cn=SYSVOL Subscription))",
                                            new string[] { "distinguishedName" },
                                            (ADItem aditem) =>
                                            {
                                                foreach (var dc in healthcheckData.DomainControllers)
                                                {
                                                    if (aditem.DistinguishedName.EndsWith(dc.DistinguishedName, StringComparison.OrdinalIgnoreCase))
                                                    {
                                                        if (dc.RODC)
                                                        {
                                                            dc.SYSVOLOverwrite = true;
                                                        }
                                                        break;
                                                    }
                                                }
                                            }
                                            );
        }

        private void GenerateRODCKrbtgtOrphans(ADDomainInfo domainInfo, ADWebService adws)
        {
            // enumerates the account with the flag "smart card required" and not disabled
            healthcheckData.RODCKrbtgtOrphans = new List<HealthcheckAccountDetailData>();
            WorkOnReturnedObjectByADWS callback =
               (ADItem x) =>
               {
                   healthcheckData.RODCKrbtgtOrphans.Add(GetAccountDetail(x));
               };

            var filter = "(&(objectclas=user)(!(msDS-KrbTgtLinkBl=*))(sAMAccountName=krbtgt_*)(msDS-SecondaryKrbTgtNumber=*))";
            adws.Enumerate(domainInfo.DefaultNamingContext, filter, CommonAccountProperties.Where(p => p != "replPropertyMetaData").ToArray(), callback);
        }

        // this function has been designed to avoid LDAP query reentrance (to avoid the 5 connection limit)
        private void GenerateFSMOData(ADDomainInfo domainInfo, ADWebService adws)
        {
            //query the NTDS objects
            string[] properties = new string[] {
                        "distinguishedName",
                        "fSMORoleOwner",
            };

            var computerToQuery = new Dictionary<string, string>();
            string role = null;
            WorkOnReturnedObjectByADWS callback =
                (ADItem x) =>
                {
                    string DN = x.fSMORoleOwner;
                    if (DN.Contains("\0"))
                    {
                        Trace.WriteLine(DN + " FSMO Warning !");
                        return;
                    }
                    string parent = DN.Substring(DN.IndexOf(",") + 1);
                    computerToQuery[role] = parent;
                };
            role = "PDC";
            adws.Enumerate(domainInfo.DefaultNamingContext, "(&(objectClass=domainDNS)(fSMORoleOwner=*))", properties, callback);
            role = "RID pool manager";
            adws.Enumerate(domainInfo.DefaultNamingContext, "(&(objectClass=rIDManager)(fSMORoleOwner=*))", properties, callback);
            role = "Infrastructure master";
            adws.Enumerate(domainInfo.DefaultNamingContext, "(&(objectClass=infrastructureUpdate)(fSMORoleOwner=*))", properties, callback);
            role = "Schema master";
            adws.Enumerate(domainInfo.SchemaNamingContext, "(&(objectClass=dMD)(fSMORoleOwner=*))", properties, callback);
            role = "Domain naming Master";
            adws.Enumerate(domainInfo.ConfigurationNamingContext, "(&(objectClass=crossRefContainer)(fSMORoleOwner=*))", properties, callback);


            foreach (var computerRole in computerToQuery.Keys)
            {
                string dns = null;
                WorkOnReturnedObjectByADWS computerCallback =
                (ADItem x) =>
                {
                    dns = x.DNSHostName;
                };
                adws.Enumerate(domainInfo.ConfigurationNamingContext, "(distinguishedName=" + ADConnection.EscapeLDAP(computerToQuery[computerRole]) + ")", new string[] { "dnsHostName" }, computerCallback);

                if (string.IsNullOrEmpty(dns))
                {
                    Trace.WriteLine("Unable to get DNSHostName for " + computerToQuery[computerRole]);
                    continue;
                }
                HealthcheckDomainController theDC = null;
                foreach (var DC in healthcheckData.DomainControllers)
                {
                    if (string.Equals(DC.DCName + "." + domainInfo.DomainName, dns, StringComparison.OrdinalIgnoreCase))
                    {
                        theDC = DC;
                        break;
                    }
                }
                if (theDC == null)
                {
                    Trace.WriteLine("Unable to get DC for " + dns);
                    continue;
                }
                if (theDC.FSMO == null)
                    theDC.FSMO = new List<string>();
                theDC.FSMO.Add(computerRole);
            }
        }

        private void GenerateCheckFRS(ADDomainInfo domainInfo, ADWebService adws)
        {
            adws.Enumerate("CN=File Replication Service,CN=System," + domainInfo.DefaultNamingContext, "(objectClass=*)", new string[] { "distinguishedName" },
                (ADItem x) =>
                {
                    if (x.DistinguishedName.Contains(",CN=Domain System Volume (SYSVOL share),"))
                    {
                        healthcheckData.UsingNTFRSForSYSVOL = true;
                    }
                }
                );
        }

        private void GenerateCheckDCConfig(ADDomainInfo domainInfo, ADWebService adws)
        {
            foreach (var dc in healthcheckData.DomainControllers)
            {
                string dn = null;
                adws.Enumerate("CN=Sites," + domainInfo.ConfigurationNamingContext, "(&(ServerReference=" + dc.DistinguishedName + ")(objectClass=server))", new string[] { "distinguishedName" },
                    (ADItem x) =>
                    {
                        dn = x.DistinguishedName;
                    }
                    );
                if (string.IsNullOrEmpty(dn))
                {
                    dc.RegistrationProblem += (string.IsNullOrEmpty(dc.RegistrationProblem) ? null : " ") + "NoConfiguration";
                }
                else
                {
                    bool NTDSNotOK = false;
                    adws.Enumerate("CN=Sites," + domainInfo.ConfigurationNamingContext, "(DistinguishedName=CN=NTDS Settings," + dn + ")", new string[] { "objectClass" },
                    (ADItem x) =>
                    {
                        if (string.Equals(x.Class, "nTDSDSA", StringComparison.OrdinalIgnoreCase) || string.Equals(x.Class, "nTDSDSARO", StringComparison.OrdinalIgnoreCase))
                        {
                            NTDSNotOK = true;
                        }
                    }
                    );
                    if (!NTDSNotOK)
                        dc.RegistrationProblem += (string.IsNullOrEmpty(dc.RegistrationProblem) ? null : " ") + "NoNTDS";
                }

            }
        }

        private void GenerateDnsData(ADDomainInfo domainInfo, ADWebService adws)
        {
            healthcheckData.DnsZones = new List<HealthcheckDnsZones>();

            if (domainInfo.NamingContexts.Contains("DC=DomainDnsZones," + domainInfo.DefaultNamingContext))
            {
                var dn = "CN=MicrosoftDNS,DC=DomainDnsZones," + domainInfo.DefaultNamingContext;
                GenerateDnsData(domainInfo, adws, dn);
            }
            else
            {
                Trace.WriteLine("No naming context for DC=DomainDnsZones," + domainInfo.DefaultNamingContext);
            }
            GenerateDnsData(domainInfo, adws, domainInfo.DefaultNamingContext);

            foreach (var zone in healthcheckData.DnsZones)
            {
                if (string.Equals(zone.name, domainInfo.DomainName, StringComparison.OrdinalIgnoreCase))
                {
                    if (DnsQuery.IsZoneTransfertActive(zone.name))
                        zone.ZoneTransfert = true;
                    break;
                }
            }
        }
        private void GenerateDnsData(ADDomainInfo domainInfo, ADWebService adws, string dn)
        {
            try
            {
                adws.Enumerate(dn, "(objectClass=dnsZone)", new string[] { "distinguishedName", "dnsProperty", "name", "nTSecurityDescriptor" },
                    (ADItem x) =>
                    {
                        var o = new HealthcheckDnsZones();
                        o.name = x.Name;
                        if (x.dnsProperty != null)
                        {
                            foreach (var p in x.dnsProperty)
                            {
                                if (p.PropertyId == ADItem.DnsPropertyId.DSPROPERTY_ZONE_ALLOW_UPDATE)
                                {
                                    if (p.Data.Length == 1 && p.Data[0] == 1)
                                    {
                                        o.InsecureUpdate = true;
                                        break;
                                    }
                                }
                            }
                        }
                        if (x.NTSecurityDescriptor != null)
                        {
                            foreach (ActiveDirectoryAccessRule accessrule in x.NTSecurityDescriptor.GetAccessRules(true, false, typeof(SecurityIdentifier)))
                            {
                                if (accessrule.AccessControlType != AccessControlType.Allow)
                                    continue;
                                SecurityIdentifier si = (SecurityIdentifier)accessrule.IdentityReference;
                                if (si.Value == "S-1-5-11" && accessrule.ObjectFlags == ObjectAceFlags.None && accessrule.InheritedObjectType == Guid.Empty && accessrule.ObjectType == Guid.Empty)
                                {
                                    if ((accessrule.ActiveDirectoryRights & ActiveDirectoryRights.CreateChild) != 0)
                                    {
                                        o.AUCreateChild = true;
                                    }
                                }
                            }
                        }
                        healthcheckData.DnsZones.Add(o);
                    }
                    );
            }
            catch (Exception ex)
            {
                // if exception 0x8007200a is thrown (The specified directory service attribute or value does not exist)
                // be sure that PingCastle is running in the highest context available (not UAC restricted)
                Trace.WriteLine("Unable to get Dns Data");
                Trace.WriteLine(ex.Message);
                Trace.WriteLine(ex.StackTrace);
            }
        }

        // see https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/5a00c890-6be5-4575-93c4-8bf8be0ca8d8
        private void CheckWellKnownObjects(ADDomainInfo domainInfo, ADWebService adws)
        {
            adws.Enumerate(domainInfo.DefaultNamingContext, "(objectClass=*)", new string[] { "wellKnownObjects" },
               (ADItem x) =>
               {
                   if (x.WellKnownObjects == null)
                       return;
                   foreach (var s in x.WellKnownObjects)
                   {
                       if (s == null)
                           continue;
                       var t = s.Split(':');
                       if (t.Length < 3)
                           continue;
                       if (t[0] == "B" && t[1] == "32")
                       {
                           switch (t[2])
                           {
                               case "AA312825768811D1ADED00C04FD8D5CD":
                                   CheckWellKnownObjects2(domainInfo, "CN=Computers", t[3]);
                                   break;
                               case "18E2EA80684F11D2B9AA00C04F79F805":
                                   CheckWellKnownObjects2(domainInfo, "CN=Deleted Objects", t[3]);
                                   break;
                               case "A361B2FFFFD211D1AA4B00C04FD7D83A":
                                   CheckWellKnownObjects2(domainInfo, "OU=Domain Controllers", t[3]);
                                   break;
                               case "22B70C67D56E4EFB91E9300FCA3DC1AA":
                                   CheckWellKnownObjects2(domainInfo, "CN=ForeignSecurityPrincipals", t[3]);
                                   break;
                               case "2FBAC1870ADE11D297C400C04FD8D5CD":
                                   CheckWellKnownObjects2(domainInfo, "CN=Infrastructure", t[3]);
                                   break;
                               case "AB8153B7768811D1ADED00C04FD8D5CD":
                                   CheckWellKnownObjects2(domainInfo, "CN=LostAndFound", t[3]);
                                   break;
                               case "F4BE92A4C777485E878E9421D53087DB":
                                   CheckWellKnownObjects2(domainInfo, "CN=Microsoft,CN=Program Data", t[3]);
                                   break;
                               case "6227F0AF1FC2410D8E3BB10615BB5B0F":
                                   CheckWellKnownObjects2(domainInfo, "CN=NTDS Quotas", t[3]);
                                   break;
                               case "09460C08AE1E4A4EA0F64AEE7DAA1E5A":
                                   CheckWellKnownObjects2(domainInfo, "CN=Program Data", t[3]);
                                   break;
                               case "AB1D30F3768811D1ADED00C04FD8D5CD":
                                   CheckWellKnownObjects2(domainInfo, "CN=System", t[3]);
                                   break;
                               case "A9D1CA15768811D1ADED00C04FD8D5CD":
                                   CheckWellKnownObjects2(domainInfo, "CN=Users", t[3]);
                                   break;
                               case "1EB93889E40C45DF9F0C64D23BBB6237":
                                   CheckWellKnownObjects2(domainInfo, "CN=Managed Service Accounts", t[3]);
                                   break;
                           }
                       }
                   }
               }
               , "Base");
        }

        void CheckWellKnownObjects2(ADDomainInfo domainInfo, string expected, string inUse)
        {
            if (expected + "," + domainInfo.DefaultNamingContext != inUse)
            {
                if (healthcheckData.DefaultOUChanged == null)
                {
                    healthcheckData.DefaultOUChanged = new List<HealthcheckOUChangedData>();
                }
                healthcheckData.DefaultOUChanged.Add(new HealthcheckOUChangedData
                {
                    Expected = expected + "," + domainInfo.DefaultNamingContext,
                    Found = inUse,
                });

            }
        }
    }
}
