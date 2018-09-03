using ADSecurityHealthCheck.ADWS;
using ADSecurityHealthCheck.Export;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Serialization;
using ADSecurityHealthCheck.Healthcheck;
using System.Threading;
using System.DirectoryServices;
using System.Security.Principal;
using System.Security.AccessControl;
using System.Net.NetworkInformation;

// TODO
// check anonymous access to the forest: https://www.stigviewer.com/stig/active_directory_forest/2014-12-18/finding/V-8555

namespace ADSecurityHealthCheck.Healthcheck
{
    public class HealthcheckAnalyzer
    {

        HealthcheckData healthcheckData;
        Dictionary<string, HealthcheckData> consolidation;

        public string GetCurrentDomain()
        {
            return healthcheckData.DomainFQDN;
        }

        private void DisplayAdvancement(string data)
        {
            string value = "[" + DateTime.Now.ToLongTimeString() + "] " + data;
            Console.WriteLine(value);
            Trace.WriteLine(value);
        }

        public void GenerateReport(string server, int port, NetworkCredential credential)
        {
            healthcheckData = new HealthcheckData();
            ADDomainInfo domainInfo = null;
            DisplayAdvancement("Getting domain information");
            using (ADWebService adws = new ADWebService(server, port, credential))
            {
                domainInfo = adws.GetDomainInfo();
                DisplayAdvancement("Gathering general data");
                GenerateGeneralData(domainInfo, adws);
                DisplayAdvancement("Gathering user data");
                GenerateUserData(domainInfo, adws);
                DisplayAdvancement("Gathering computer data");
                GenerateComputerData(domainInfo, adws);
                DisplayAdvancement("Gathering trust data");
                GenerateTrustData(domainInfo, adws);
                DisplayAdvancement("Gathering privileged group data");
                GeneratePrivilegedGroupData(domainInfo, adws);
                DisplayAdvancement("Gathering delegation data");
                GenerateDelegationData(domainInfo, adws);
                //DisplayAdvancement("Gathering topology data");
                //GenerateTopologyData(domainInfo, adws);
                DisplayAdvancement("Gathering gpo data");
                GenerateGPOData(domainInfo, adws, credential);
                DisplayAdvancement("Gathering anomaly data");
                GenerateAnomalies(domainInfo, adws);
            }
            DisplayAdvancement("Computing risks");
            HealthcheckRules.ComputeRiskRules(healthcheckData);
            DisplayAdvancement("Export completed");

        }



        //static void test()
        //{
        //    XmlDocument xmldoc = new XmlDocument();
        //    xmldoc.PreserveWhitespace = true;
        //    XmlNode msgnode =
        //       xmldoc.CreateNode(XmlNodeType.Element, "Plaintext", "msg");
        //    msgnode.InnerText = "This is the plaintext message.";
        //    xmldoc.AppendChild(msgnode);
        //    System.Security.Cryptography.Xml.SignedXml XMLsig = new System.Security.Cryptography.Xml.SignedXml();
        //    System.Security.Cryptography.RSA keypair = System.Security.Cryptography.RSA.Create(); XMLsig.SigningKey = keypair;
        //    System.Security.Cryptography.Xml.DataObject message =
        //     new System.Security.Cryptography.Xml.DataObject("Message", "", "", xmldoc.DocumentElement);
        //    XMLsig.AddObject(message);
        //    System.Security.Cryptography.Xml.Reference msgURI = new System.Security.Cryptography.Xml.Reference();
        //    msgURI.Uri = "#Message";
        //    XMLsig.AddReference(msgURI);
        //    System.Security.Cryptography.Xml.KeyInfo ki = new System.Security.Cryptography.Xml.KeyInfo();
        //    ki.AddClause(new System.Security.Cryptography.Xml.RSAKeyValue(keypair));
        //    XMLsig.KeyInfo = ki;
        //    XMLsig.ComputeSignature();
        //    Console.Out.WriteLine(XMLsig.GetXml().OuterXml);
        //}

        public void SaveAsXml(string filename, HealthcheckDataLevel Level)
        {
            healthcheckData.Level = Level;
            XmlSerializer xs = new XmlSerializer(typeof(HealthcheckData));
            using (StreamWriter wr = new StreamWriter(filename))
            {
                xs.Serialize(wr, healthcheckData);
            }
        }

        public void LoadXmls(string Xmls)
        {
            consolidation = new Dictionary<string, HealthcheckData>();
            foreach (string filename in Directory.GetFiles(Xmls, "*.xml", SearchOption.AllDirectories))
            {
                try
                {
                    LoadXml(filename);
                    // taking the more recent report
                    if (consolidation.ContainsKey(healthcheckData.DomainFQDN))
                    {
                        if (consolidation[healthcheckData.DomainFQDN].GenerationDate < healthcheckData.GenerationDate)
                        {
                            consolidation[healthcheckData.DomainFQDN] = healthcheckData;
                        }
                    }
                    else
                    {
                        consolidation.Add(healthcheckData.DomainFQDN, healthcheckData);
                    }

                }
                catch (Exception ex)
                {
                    lock (Console.Out)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Unable to load the file " + filename + "(" + ex.Message + ")");
                        Console.ResetColor();
                    }
                    Trace.WriteLine("Unable to load the file " + filename + "(" + ex.Message + ")");
                    Trace.WriteLine(ex.StackTrace);
                }
            }
        }

        public void LoadXml(string filename)
        {
            XmlSerializer xs = new XmlSerializer(typeof(HealthcheckData));
            using (StreamReader wr = new StreamReader(filename))
            {
                healthcheckData = xs.Deserialize(wr) as HealthcheckData;
            }
        }

        public void GenerateReportFile(string filename)
        {
            HealthCheckReport report = new HealthCheckReport(healthcheckData);
            report.GenerateReportFile(filename);
        }

        public void GenerateConsolidatedReport(string filename)
        {
            HealthCheckReport report = new HealthCheckReport(consolidation);
            report.GenerateConsolidatedReportFile(filename);
        }

        public void GenerateGroupReport(string reportfilename)
        {
            HealthCheckExcelReport report = new HealthCheckExcelReport(consolidation);
            report.GenerateGroupReport(reportfilename);

        }

        public void GenerateTrustNodeMap(string filename)
        {
            HealthCheckNodeAnalyzer report = new HealthCheckNodeAnalyzer(consolidation);
            report.GenerateTrustNodeMap(filename);
        }

        public List<string> GetAllReachableDomains(int port, NetworkCredential credential)
        {
            List<string> domains = new List<string>();
            List<string> domainsInError = new List<string>();
            string root = IPGlobalProperties.GetIPGlobalProperties().DomainName.ToLowerInvariant();
            if (String.IsNullOrEmpty(root))
                return domains;
            ExploreReachableDomain(root, "current domain", port, credential, domains, domainsInError, 1);
            // sort the domain by name
            domains.Sort();
            return domains;
        }

        private void ExploreReachableDomain(string domainToExplore, string sourceForDisplay, int port, NetworkCredential credential,
                                                            List<string> domainlist, List<string> domainInError,
                                                        int distance)
        {
            // classic graph exploration algorithm
            string[] properties = new string[] {
                        "trustPartner",
                        "trustAttributes",
                        "trustDirection",
                        "trustType",
            };
            // key = domain , value = distance
            List<KeyValuePair<string, int>> domainOnHold = new List<KeyValuePair<string, int>>();
            WorkOnReturnedObjectByADWS callback =
                (ADItem x) =>
                {
                    if (domainlist.Contains(x.TrustPartner.ToLowerInvariant()) || domainInError.Contains(x.TrustPartner.ToLowerInvariant()))
                        return;
                    // inbound trust
                    if (x.TrustDirection == 2)
                        return;
                    int newdistance = distance - 1;
                    // do not reduce the distance in intra-forest trust
                    if ((x.TrustAttributes & 32) != 0)
                        newdistance = distance;
                    if (newdistance >= 0)
                    {
                        domainOnHold.Add(new KeyValuePair<string, int>(x.TrustPartner.ToLowerInvariant(), newdistance));
                    }
                };
            ADWebService adws = null;
            try
            {
                DisplayAdvancement("Exploring " + domainToExplore + " (source:" + sourceForDisplay + ")");
                adws = new ADWebService(domainToExplore, port, credential);
                ADDomainInfo domainInfo = adws.GetDomainInfo();
                // if we are here that means that ADWS works
                domainlist.Add(domainToExplore);
                adws.Enumerate(domainInfo.DefaultNamingContext, "(ObjectCategory=trustedDomain)", properties, callback);
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Unable to expore " + domainToExplore + " (" + ex.Message + ")");
                Console.ResetColor();
                Trace.WriteLine("Unable to expore " + domainToExplore + " (" + ex.Message + ")");
                Trace.WriteLine(ex.StackTrace);
                domainInError.Add(domainToExplore);
            }
            finally
            {
                adws.Dispose();
            }
            // sort the value of the domain to examine by proximity then by name
            domainOnHold.Sort(
                (KeyValuePair<string, int> a, KeyValuePair<string, int> b)
                    =>
                {
                    if (a.Value == b.Value)
                        return String.Compare(a.Key, b.Key);
                    if (a.Value > b.Value)
                        return 1;
                    return -1;
                }
                );
            foreach (KeyValuePair<string, int> domain in domainOnHold)
            {
                // avoid side effect with ExploreReachableDomain which can modify the lists of known domwains
                if (domainlist.Contains(domain.Key) || domainInError.Contains(domain.Key))
                    continue;
                ExploreReachableDomain(domain.Key, domainToExplore, port, credential, domainlist, domainInError, domain.Value);
            }
        }


        private void GenerateGeneralData(ADDomainInfo domainInfo, ADWebService adws)
        {
            // adding the domain sid
            string[] properties = new string[] { "objectSid", "whenCreated" };
            adws.Enumerate(domainInfo.DefaultNamingContext,
                                            "(&(objectClass=domain)(distinguishedName=" + domainInfo.DefaultNamingContext + "))",
                                            properties, (ADItem aditem) => { domainInfo.DomainSid = aditem.ObjectSid; domainInfo.CreationDate = aditem.WhenCreated; });

            healthcheckData.DomainFQDN = domainInfo.DomainName;
            if (domainInfo.DomainSid != null)
                healthcheckData.DomainSid = domainInfo.DomainSid.Value;
            healthcheckData.DomainCreation = domainInfo.CreationDate;

            // adding the domain Netbios name
            string[] propertiesNetbios = new string[] { "nETBIOSName" };
            adws.Enumerate("CN=Partitions," + domainInfo.ConfigurationNamingContext,
                                            "(&(objectCategory=crossRef)(systemFlags:1.2.840.113556.1.4.803:=3)(nETBIOSName=*)(nCName="+domainInfo.DefaultNamingContext+"))",
                                            propertiesNetbios, (ADItem aditem) => { domainInfo.NetBIOSName = aditem.NetBIOSName; }, "OneLevel");

            healthcheckData.NetBIOSName = domainInfo.NetBIOSName;
            healthcheckData.ForestFunctionalLevel = domainInfo.ForestFunctionality;
            healthcheckData.DomainFunctionalLevel = domainInfo.DomainFunctionality;
            healthcheckData.GenerationDate = DateTime.Now;
            Version version = Assembly.GetExecutingAssembly().GetName().Version;
            healthcheckData.EngineVersion = version.ToString(3);
            healthcheckData.Level = HealthcheckDataLevel.Full;
        }


        private void GenerateUserData(ADDomainInfo domainInfo, ADWebService adws)
        {
            Dictionary<string, int> loginscript = new Dictionary<string, int>();
            string[] properties = new string[] {
                        "objectSid",
                        "distinguishedName",
                        "name",
                        "scriptPath",
                        "primaryGroupID",
                        "sIDHistory",
                        "lastLogonTimestamp",
                        "userAccountControl",
                        "pwdLastSet",
                        "msDS-SupportedEncryptionTypes",
                        "whenCreated",
            };

            healthcheckData.UserAccountData = new HealthcheckAccountData();

            WorkOnReturnedObjectByADWS callback =
                (ADItem x) =>
                {
                    // krbtgt
                    if (x.ObjectSid.IsWellKnown(System.Security.Principal.WellKnownSidType.AccountKrbtgtSid))
                    {
                        healthcheckData.KrbtgtLastChangeDate = x.PwdLastSet;
                        return;
                    }
                    // admin account
                    if (x.ObjectSid.IsWellKnown(System.Security.Principal.WellKnownSidType.AccountAdministratorSid))
                    {
                        healthcheckData.AdminLastLoginDate = x.LastLogonTimestamp;
                    }
                    // ignore trust account
                    if (x.Name.EndsWith("$", StringComparison.InvariantCultureIgnoreCase) && ((x.UserAccountControl & 2048) != 0))
                    {
                        return;
                    }
                    ProcessAccountData(healthcheckData.UserAccountData, x, false);
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
                };

            adws.Enumerate(domainInfo.DefaultNamingContext, "(&(objectClass=user)(objectCategory=person))", properties, callback);
            healthcheckData.LoginScript = new List<HealthcheckLoginScriptData>();
            foreach (string key in loginscript.Keys)
            {
                healthcheckData.LoginScript.Add(new HealthcheckLoginScriptData(key, loginscript[key]));
            }
        }

        void ProcessAccountData(HealthcheckAccountData data, ADItem x, bool computerCheck)
        {
            // see https://msdn.microsoft.com/fr-fr/library/windows/desktop/ms680832%28v=vs.85%29.aspx for the flag
            data.Number++;
            if ((x.UserAccountControl & 0x00000002) != 0)
                data.NumberDisabled++;
            else
            {
                data.NumberEnabled++;
                if (x.LastLogonTimestamp.AddDays(6 * 31) > DateTime.Now)
                    data.NumberActive++;
                else
                {
                    data.NumberInactive++;
                    if (data.ListInactive == null)
                        data.ListInactive = new List<HealthcheckAccountDetailData>();
                    data.ListInactive.Add(GetAccountDetail(x));
                }
                if ((x.UserAccountControl & 0x00000010) != 0)
                {
                    data.NumberLocked++;
                    if (data.ListLocked == null)
                        data.ListLocked = new List<HealthcheckAccountDetailData>();
                    data.ListLocked.Add(GetAccountDetail(x));
                }
                if ((x.UserAccountControl & 0x00010000) != 0)
                {
                    data.NumberPwdNeverExpires++;
                    if (data.ListPwdNeverExpires == null)
                        data.ListPwdNeverExpires = new List<HealthcheckAccountDetailData>();
                    data.ListPwdNeverExpires.Add(GetAccountDetail(x));
                }
                if ((x.UserAccountControl & 0x00000020) != 0)
                {
                    data.NumberPwdNotRequired++;
                    if (data.ListPwdNotRequired == null)
                        data.ListPwdNotRequired = new List<HealthcheckAccountDetailData>();
                    data.ListPwdNotRequired.Add(GetAccountDetail(x));
                }
                if (x.SIDHistory != null && x.SIDHistory.Length > 0)
                {
                    data.NumberSidHistory++;
                    if (data.ListSidHistory == null)
                        data.ListSidHistory = new List<HealthcheckAccountDetailData>();
                    data.ListSidHistory.Add(GetAccountDetail(x));
                }
                if (!computerCheck)
                {
                    if (x.PrimaryGroupID != 513 && !x.ObjectSid.IsWellKnown(System.Security.Principal.WellKnownSidType.AccountGuestSid))
                    {
                        data.NumberBadPrimaryGroup++;
                        if (data.ListBadPrimaryGroup == null)
                            data.ListBadPrimaryGroup = new List<HealthcheckAccountDetailData>();
                        data.ListBadPrimaryGroup.Add(GetAccountDetail(x));
                    }
                }
                else
                {
                    if (x.PrimaryGroupID != 515)
                    {
                        if ((x.PrimaryGroupID == 516 || x.PrimaryGroupID == 521) && x.DistinguishedName.Contains("OU=Domain Controllers,DC="))
                        {
                            // ignore domain controller group
                            // 516 = RW DC, 521 = RO DC
                        }
                        else
                        {
                            data.NumberBadPrimaryGroup++;
                            if (data.ListBadPrimaryGroup == null)
                                data.ListBadPrimaryGroup = new List<HealthcheckAccountDetailData>();
                            data.ListBadPrimaryGroup.Add(GetAccountDetail(x));
                        }
                    }
                }
                // see [MS-KILE] && https://blogs.msdn.microsoft.com/openspecification/2011/05/30/windows-configurations-for-kerberos-supported-encryption-type/
                // msDSSupportedEncryptionTypes =1 => DES-CBC-CRC ; 2 => DES-CBC-MD5
                if (((x.UserAccountControl & 0x00200000) != 0) || ((x.msDSSupportedEncryptionTypes & (1 | 2)) > 0))
                {
                    data.NumberDesEnabled++;
                    if (data.ListDesEnabled == null)
                        data.ListDesEnabled = new List<HealthcheckAccountDetailData>();
                    data.ListDesEnabled.Add(GetAccountDetail(x));
                }
                if ((x.UserAccountControl & 0x01000000) != 0)
                {
                    data.NumberTrustedToAuthenticateForDelegation++;
                    if (data.ListTrustedToAuthenticateForDelegation == null)
                        data.ListTrustedToAuthenticateForDelegation = new List<HealthcheckAccountDetailData>();
                    data.ListTrustedToAuthenticateForDelegation.Add(GetAccountDetail(x));
                }
                if ((x.UserAccountControl & 0x0080) != 0)
                {
                    data.NumberReversibleEncryption++;
                    if (data.ListReversibleEncryption == null)
                        data.ListReversibleEncryption = new List<HealthcheckAccountDetailData>();
                    data.ListReversibleEncryption.Add(GetAccountDetail(x));
                }
                
            }

        }

        private HealthcheckAccountDetailData GetAccountDetail(ADItem x)
        {
            HealthcheckAccountDetailData data = new HealthcheckAccountDetailData();
            data.DistinguishedName = x.DistinguishedName;
            data.Name = x.Name;
            data.CreationDate = x.WhenCreated;
            data.LastLogonDate = x.LastLogonTimestamp;
            return data;
        }

        private void GenerateComputerData(ADDomainInfo domainInfo, ADWebService adws)
        {
            string[] properties = new string[] {"objectSid",
                        "distinguishedName",
                        "name",
                        "operatingSystem",
                        "primaryGroupID",
                        "sIDHistory",
                        "userAccountControl",
                        "whenCreated",
                        "lastLogonTimestamp",
            };

            Dictionary<string, int> operatingSystems = new Dictionary<string, int>();
            Dictionary<string, int> operatingSystemsDC = new Dictionary<string, int>();
            healthcheckData.ComputerAccountData = new HealthcheckAccountData();

            WorkOnReturnedObjectByADWS callback =
                (ADItem x) =>
                {
                    ProcessAccountData(healthcheckData.ComputerAccountData, x, true);
                    string os = GetOperatingSystem(x.OperatingSystem);
                    if (!operatingSystems.ContainsKey(os))
                    {
                        operatingSystems[os] = 1;
                    }
                    else
                    {
                        operatingSystems[os]++;
                    }
                    if (x.PrimaryGroupID == 516 || x.PrimaryGroupID == 521)
                    {
                        healthcheckData.NumberOfDC++;
                        if (!operatingSystemsDC.ContainsKey(os))
                        {
                            operatingSystemsDC[os] = 1;
                        }
                        else
                        {
                            operatingSystemsDC[os]++;
                        }
                    }
                    // domain controllers enabled
                    if (x.DistinguishedName.Contains("OU=Domain Controllers,DC=") && ((x.UserAccountControl & 0x00000002) == 0))
                    {
                        // last logon timestam can have a delta of 14 days
                        if (x.LastLogonTimestamp.AddDays(60) < DateTime.Now)
                        {
                            if (healthcheckData.DCNotUptodate == null)
                                healthcheckData.DCNotUptodate = new List<string>();
                            healthcheckData.DCNotUptodate.Add(x.Name);
                        }
                    }
                };

            adws.Enumerate(domainInfo.DefaultNamingContext, "(&(ObjectCategory=computer))", properties, callback);
            healthcheckData.OperatingSystem = new List<HealthcheckOSData>();
            foreach (string key in operatingSystems.Keys)
            {
                healthcheckData.OperatingSystem.Add(new HealthcheckOSData(key, operatingSystems[key]));
            }
            healthcheckData.OperatingSystemDC = new List<HealthcheckOSData>();
            foreach (string key in operatingSystemsDC.Keys)
            {
                healthcheckData.OperatingSystemDC.Add(new HealthcheckOSData(key, operatingSystemsDC[key]));
            }
        }

        private string GetOperatingSystem(string os)
        {
            if (String.IsNullOrEmpty(os))
            {
                return "OperatingSystem not set";
            }
            if (Regex.Match(os, @"windows(.*)2000", RegexOptions.IgnoreCase).Success)
            {
                return "Windows 2000";
            }
            if (Regex.Match(os, @"windows(.*)2003", RegexOptions.IgnoreCase).Success)
            {
                return "Windows 2003";
            }
            if (Regex.Match(os, @"windows(.*)2008", RegexOptions.IgnoreCase).Success)
            {
                return "Windows 2008";
            }
            if (Regex.Match(os, @"windows(.*)2012", RegexOptions.IgnoreCase).Success)
            {
                return "Windows 2012";
            }
            if (Regex.Match(os, @"windows(.*)7", RegexOptions.IgnoreCase).Success)
            {
                return "Windows 7";
            }
            if (Regex.Match(os, @"windows(.*) 8", RegexOptions.IgnoreCase).Success)
            {
                return "Windows 8";
            }
            if (Regex.Match(os, @"windows(.*)Embedded", RegexOptions.IgnoreCase).Success)
            {
                return "Windows Embedded";
            }
            if (Regex.Match(os, @"windows(.*)XP", RegexOptions.IgnoreCase).Success)
            {
                return "Windows XP";
            }
            if (Regex.Match(os, @"windows(.*)10", RegexOptions.IgnoreCase).Success)
            {
                return "Windows 10";
            }
            if (Regex.Match(os, @"windows(.*)Vista", RegexOptions.IgnoreCase).Success)
            {
                return "Windows Vista";
            }
            if (Regex.Match(os, @"windows(.*)NT", RegexOptions.IgnoreCase).Success)
            {
                return "Windows NT";
            }
            return os;
        }

        private void GenerateTrustData(ADDomainInfo domainInfo, ADWebService adws)
        {
            string[] properties = new string[] {
                        "distinguishedName",
                        "securityIdentifier",
                        "trustPartner",
                        "trustAttributes",
                        "trustDirection",
                        "trustType",
                        "whenCreated",
                        "whenChanged",
            };
            WorkOnReturnedObjectByADWS callback =
                (ADItem x) =>
                {
                    if (healthcheckData.Trusts == null)
                    {
                        healthcheckData.Trusts = new List<HealthCheckTrustData>();
                    }
                    HealthCheckTrustData trust = new HealthCheckTrustData();
                    healthcheckData.Trusts.Add(trust);
                    trust.TrustPartner = x.TrustPartner.ToLowerInvariant();
                    trust.TrustAttributes = x.TrustAttributes;
                    trust.TrustDirection = x.TrustDirection;
                    trust.TrustType = x.TrustType;
                    trust.CreationDate = x.WhenCreated;
                    // if a trust is active, the password is changed every 30 days
                    // so the object will be changed
                    trust.IsActive = (x.WhenChanged.AddDays(60) > DateTime.Now);
                    // sid is used to translate unknown FSP
                    if (x.SecurityIdentifier != null)
                    {
                        trust.SID = x.SecurityIdentifier.Value;
                    }
                };

            adws.Enumerate(domainInfo.DefaultNamingContext, "(ObjectCategory=trustedDomain)", properties, callback);
        }

        private void GeneratePrivilegedGroupData(ADDomainInfo domainInfo, ADWebService adws)
        {
            healthcheckData.PrivilegedGroups = new List<HealthCheckGroupData>();
            healthcheckData.AllPrivilegedMembers = new List<HealthCheckGroupMemberData>();

            // this is the list of group to analyze
            KeyValuePair<string, string>[] privilegedGroups = new KeyValuePair<string, string>[]{
                new KeyValuePair<string, string>("S-1-5-32-544","Administrators"),
                new KeyValuePair<string, string>("S-1-5-32-548","Account Operators"),
                new KeyValuePair<string, string>("S-1-5-32-549","Server Operators"),
                new KeyValuePair<string, string>("S-1-5-32-550","Print Operators"),
                new KeyValuePair<string, string>("S-1-5-32-551","Backup Operators"),
                new KeyValuePair<string, string>("S-1-5-32-569","Crypto Operators"),
                new KeyValuePair<string, string>("S-1-5-32-557","Incoming Forest Trust Builders"),
                new KeyValuePair<string, string>("S-1-5-32-556","Network Operators"),
                new KeyValuePair<string, string>(domainInfo.DomainSid + "-512","Domain Admins"),
                new KeyValuePair<string, string>(domainInfo.DomainSid + "-519","Enterprise Admins"),
                new KeyValuePair<string, string>(domainInfo.DomainSid + "-518","Schema Admins"),
                new KeyValuePair<string, string>(domainInfo.DomainSid + "-517","Cert Publishers"),
            };
            Dictionary<string, HealthCheckGroupMemberData> allMembers = new Dictionary<string, HealthCheckGroupMemberData>();
            foreach (KeyValuePair<string, string> privilegedGroup in privilegedGroups)
            {
                Trace.WriteLine("Working on group " + privilegedGroup.Value);
                Dictionary<string, ADItem> members = new Dictionary<string, ADItem>();
                List<string> knownItems = new List<string>();
                
                if (GetGroupMembers(domainInfo, adws, privilegedGroup.Key, members, knownItems, 0))
                {
                    HealthCheckGroupData data = AnalyzeGroupData(domainInfo, privilegedGroup.Value, members);
                    healthcheckData.PrivilegedGroups.Add(data);
                    foreach (HealthCheckGroupMemberData member in data.Members)
                    {
                        if (!allMembers.ContainsKey(member.DistinguishedName))
                        {
                            allMembers.Add(member.DistinguishedName, member);
                        }
                    }
                }
            }
            foreach (HealthCheckGroupMemberData member in allMembers.Values)
            {
                healthcheckData.AllPrivilegedMembers.Add(member);
            }
        }

        private HealthCheckGroupData AnalyzeGroupData(ADDomainInfo domainInfo, string groupName, Dictionary<string, ADItem> members)
        {
            HealthCheckGroupData data = new HealthCheckGroupData();
            data.GroupName = groupName;
            data.Members = new List<HealthCheckGroupMemberData>();
            foreach (ADItem x in members.Values)
            {
                // avoid computer included in the "cert publisher" group
                if (x.Class == "computer")
                    continue;
                data.NumberOfMember++;
                HealthCheckGroupMemberData member = new HealthCheckGroupMemberData();
                data.Members.Add(member);
                member.DistinguishedName = x.DistinguishedName;
                // special case for foreignsecurityprincipals
                if (x.Class != "user")
                {
                    data.NumberOfExternalMember++;
                    member.IsExternal = true;
                    member.Name = x.Name;
                    if (x.Name.StartsWith("S-1-", StringComparison.InvariantCultureIgnoreCase))
                    {
                        // try to solve the SID
                        member.Name = NativeMethods.ConvertSIDToName(x.Name, domainInfo.DnsHostName);
                    }
                }
                else
                {
                    // analyse useraccountcontrol
                    member.Name = x.SAMAccountName;
                    if ((x.UserAccountControl & 0x00000002) != 0)
                        data.NumberOfMemberDisabled++;
                    else
                    {
                        data.NumberOfMemberEnabled++;
                        member.IsEnabled = true;
                        // last login since 6 months
                        if (x.LastLogonTimestamp.AddDays(6 * 31) > DateTime.Now)
                        {
                            data.NumberOfMemberActive++;
                            member.IsActive = true;
                        }
                        else
                            data.NumberOfMemberInactive++;
                    }
                    if ((x.UserAccountControl & 0x00000010) != 0)
                    {
                        member.IsLocked = true;
                        data.NumberOfMemberLocked++;
                    }
                    if ((x.UserAccountControl & 0x00010000) != 0)
                    {
                        data.NumberOfMemberPwdNeverExpires++;
                        member.DoesPwdNeverExpires = true;
                    }
                    if ((x.UserAccountControl & 0x00000020) != 0)
                        data.NumberOfMemberPwdNotRequired++;
                    // this account is sensitive and cannot be delegated
                    if ((x.UserAccountControl & 0x100000) == 0)
                    {
                        data.NumberOfMemberCanBeDelegated++;
                        member.CanBeDelegated = true;
                    }
                }
            }
            return data;
        }

        // this function is used instead of Get-ADGroupMember because this function doesn't handle ForeignSecurityPrincipals
        // this function should avoid calling ws-enumerate in the middle of a ws-enumerate operation to avoid the limit of 5 ws-enumeration handles
        private bool GetGroupMembers(ADDomainInfo domainInfo, ADWebService adws, string dataToSearch, Dictionary<string, ADItem> output, List<string> knownItems, int searchType)
        {
            // knownItems is here to avoid a group1 -> group2 -> group1 -> group2 loop
            if (knownItems.Contains(dataToSearch))
                return false;
            knownItems.Add(dataToSearch);
            string[] properties = new string[] {
                        "distinguishedName",
                        "objectSid",
                        "member",
                        "name",
                        "userAccountControl",
                        "lastLogonTimestamp",
                        "sAMAccountName",
            };
            bool IsObjectFound = false;
            List<string> FutureDataToSearch = new List<string>();
            WorkOnReturnedObjectByADWS callback =
                (ADItem x) =>
                {
                    IsObjectFound = true;
                    if (output.ContainsKey(x.DistinguishedName))
                        return;

                    // mapping using primarygroup / sidhistory is ignored on purpose
                    // (checked on the user section)
                    if (x.Member != null)
                    {
                        foreach (string member in x.Member)
                        {
                            // queue search
                            FutureDataToSearch.Add(member);
                        }
                    }
                    if (x.Class != "group")
                    {
                        output.Add(x.DistinguishedName, x);
                    }
                }
            ;
            string ldapSearch;
            switch (searchType)
            {
                case 0:
                    ldapSearch = "(objectSID=" + dataToSearch + ")";
                    break;
                default:
                    ldapSearch = "(distinguishedName=" + dataToSearch + ")";
                    break;
            }
            adws.Enumerate(domainInfo.DefaultNamingContext, ldapSearch, properties, callback);
            // work on queued items
            foreach (string currentDataToSearch in FutureDataToSearch)
            {
                if (!output.ContainsKey(currentDataToSearch))
                {
                    // the item can refer to another domain of the forest
                    if (IsDCMatchDomain(currentDataToSearch, domainInfo.DefaultNamingContext))
                    {
                        GetGroupMembers(domainInfo, adws, currentDataToSearch, output, knownItems, 1);
                    }
                    else
                    {
                        ADItem x = new ADItem();
                        x.DistinguishedName = currentDataToSearch;
                        x.Name = GetDisplayName(currentDataToSearch);
                        output.Add(x.DistinguishedName, x);
                    }
                }
            }
            return IsObjectFound;
        }

        Regex re = new Regex(@"^CN=(?<cn>.+?)(?<!\\),(?<ou>(?:(?:OU|CN).+?(?<!\\),)*(?<dc>DC.+?))$");

        private bool IsDCMatchDomain(string dn, string dc)
        {
            Match m = re.Match(dn);
            if (!m.Success)
                return false;
            return m.Groups[3].Value.Equals(dc, StringComparison.InvariantCultureIgnoreCase);
        }

        private string GetDisplayName(string dn)
        {
            Match m = re.Match(dn);
            if (!m.Success)
                return dn;
            return m.Groups[1].Value;
        }

        private void GenerateDelegationData(ADDomainInfo domainInfo, ADWebService adws)
        {
            healthcheckData.Delegations = new List<HealthcheckDelegationData>();
            InspectAdminSDHolder(domainInfo, adws);
            InspectDelegation(domainInfo, adws);
        }

        //static string AdminSDHolderSDDL13 =
        //    @"O:S-1-5-21-1330137634-1750626333-945493308-512G:S-1-5-21-1330137634-1750626333-945493308-512D:PAI(A;;LCRPLORC;;;AU)(A;;CCDCLCSWRPWPLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPLOCRRCWDWO;;;S-1-5-21-1330137634-1750626333-945493308-519)(A;;CCDCLCSWRPWPLOCRRCWDWO;;;S-1-5-21-1330137634-1750626333-945493308-512)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(OA;;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;LCRPLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)S:AI(AU;CIIDSAFA;CCDCSWWPDTCRSDWDWO;;;WD)";
        //static string AdminSDHolderSDDL30 =
        //    @"O:DAG:DAD:PAI(A;;LCRPLORC;;;AU)(A;;CCDCLCSWRPWPLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPLOCRRCWDWO;;;EA)(A;;CCDCLCSWRPWPLOCRRCWDWO;;;DA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(OA;;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;LCRPLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;CA)(OA;;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;LCRPLORC;;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)(OA;;RPWP;6db69a1c-9422-11d1-aebd-0000f80367c1;;S-1-5-32-561)S:AI(AU;SA;WPWDWO;;;WD)(OU;CIIOIDSA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)(OU;CIIOIDSA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)";
        //static string AdminSDHolderSDDL44 =
        //    @"O:DAG:DAD:PAI(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;CA)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)(OA;;RPWP;6db69a1c-9422-11d1-aebd-0000f80367c1;;S-1-5-32-561)(OA;;RPWP;5805bc62-bdc9-4428-a5e2-856a0f4c185e;;S-1-5-32-561)(OA;;LCRPLORC;;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;LCRPLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;PS)(OA;CI;RPWPCR;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;PS)(A;;CCDCLCSWRPWPLOCRRCWDWO;;;DA)(A;;CCDCLCSWRPWPLOCRRCWDWO;;;EA)(A;;CCDCLCSWRPWPLOCRSDRCWDWO;;;BA)(A;;LCRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)S:AI(AU;SA;WPWDWO;;;WD)(OU;CIIOIDSA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)(OU;CIIOIDSA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)";
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

            adws.Enumerate(domainInfo.DefaultNamingContext, "(distinguishedName=CN=AdminSDHolder,CN=System,"+domainInfo.DefaultNamingContext+")", properties, callback);

            ActiveDirectorySecurity reference = new ActiveDirectorySecurity();
            string sddlToCheck = AdminSDHolder.GetSecurityDescriptorSddlForm(AccessControlSections.Access);
            //reference.SetSecurityDescriptorSddlForm(AdminSDHolderSDDL44);
            List<string> rulesAdded = CompareSecurityDescriptor(sddlToCheck, sddlReference, domainInfo.DomainSid);
            AddAdminSDHolderSDDLRulesToDelegation(rulesAdded, domainInfo);
        }

        private void AddAdminSDHolderSDDLRulesToDelegation(List<string> rulesAdded, ADDomainInfo domainInfo)
        {
            Dictionary<string, string> dic = new Dictionary<string, string>();
            foreach (string rule in rulesAdded)
            {
                string[] SDDL = rule.Split(';');
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
                data.Account = NativeMethods.ConvertSIDToName(key, domainInfo.DnsHostName);
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
            sddlToCheck = Regex.Replace(sddlToCheck,@"S-1-5-21-\d+-\d+-\d+-519", "EA");
            //sddlToCheck = sddlToCheck.Replace(new SecurityIdentifier(WellKnownSidType.AccountEnterpriseAdminsSid, domain).Value, "EA");
            sddlToCheck = sddlToCheck.Replace(new SecurityIdentifier(WellKnownSidType.AccountCertAdminsSid, domain).Value, "CA");
            
            string[] values = sddlToCheck.Split(new string[]{"(",")"},StringSplitOptions.RemoveEmptyEntries);
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
            string[] properties = new string[] {
                        "distinguishedName",
                        "name",
                        "nTSecurityDescriptor",
            };
            WorkOnReturnedObjectByADWS callback =
                (ADItem x) =>
                {
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
                        healthcheckData.Delegations.Add(delegation);
                        delegation.DistinguishedName = x.DistinguishedName;
                        // avoid translation for anomaly detection later
                        if (sid == "S-1-1-0")
                        {
                            delegation.Account = "Everyone";
                        }
                        else if (sid == "S-1-5-11")
                        {
                            delegation.Account = "Authenticated Users";
                        }
                        else
                        {
                            delegation.Account = NativeMethods.ConvertSIDToName(sid, domainInfo.DnsHostName);
                        }
                        delegation.Right = permissions[sid];
                    }

                };

            adws.Enumerate(domainInfo.DefaultNamingContext, "(ObjectClass=organizationalUnit)", properties, callback);
        }

        static KeyValuePair<Guid, string>[] GuidsControlExtendedRights = new KeyValuePair<Guid, string>[] { 
                    new KeyValuePair<Guid, string>(new Guid("00299570-246d-11d0-a768-00aa006e0529"), "EXT_RIGHT_FORCE_CHANGE_PWD"),
                    new KeyValuePair<Guid, string>(new Guid("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"), "EXT_RIGHT_REPLICATION_GET_CHANGES_ALL"),
                    new KeyValuePair<Guid, string>(new Guid("45ec5156-db7e-47bb-b53f-dbeb2d03c40f"), "EXT_RIGHT_REANIMATE_TOMBSTONE"),
                    new KeyValuePair<Guid, string>(new Guid("ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501"), "EXT_RIGHT_UNEXPIRE_PASSWORD"),
                    new KeyValuePair<Guid, string>(new Guid("ba33815a-4f93-4c76-87f3-57574bff8109"), "EXT_RIGHT_MIGRATE_SID_HISTORY"),
                };

        static KeyValuePair<Guid, string>[] GuidsControlValidatedWrites = new KeyValuePair<Guid, string>[] { 
                        new KeyValuePair<Guid, string>(new Guid("bc0ac240-79a9-11d0-9020-00c04fc2d4cf"),"WRITE_PROPSET_MEMBERSHIP"),
                    };

        static KeyValuePair<Guid, string>[] GuidsControlProperties = new KeyValuePair<Guid, string>[] { 
                        new KeyValuePair<Guid, string>(new Guid("bf9679c0-0de6-11d0-a285-00aa003049e2"),"WRITE_PROP_MEMBER"),
                        new KeyValuePair<Guid, string>(new Guid("f30e3bbe-9ff0-11d1-b603-0000f80367c1"),"WRITE_PROP_GPLINK"),
                        new KeyValuePair<Guid, string>(new Guid("f30e3bc1-9ff0-11d0-b603-0000f80367c1"),"WRITE_PROP_GPC_FILE_SYS_PATH"),
                    };
        static KeyValuePair<Guid, string>[] GuidsControlPropertiesSets = new KeyValuePair<Guid, string>[] { 
                        new KeyValuePair<Guid, string>(new Guid("bf9679c0-0de6-11d0-a285-00aa003049e2"),"VAL_WRITE_SELF_MEMBERSHIP"),
                    };

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
                // check each ACL for well known SID
                //if (si.IsEqualDomainSid(domainInfo.DomainSid))
                //{
                //    bool WellKnownSid = false;
                //    for (int i = 0; i < (int)WellKnownSidType.MaxDefined; i++)
                //    {
                //        if (si.IsWellKnown((WellKnownSidType)i))
                //        {
                //            WellKnownSid = true;
                //            break;
                //        }
                //    }
                //    if (WellKnownSid)
                //        continue;
                //}
                // remove exchange admins
                //string account = NativeMethods.ConvertSIDToName(si.Value, domainInfo.DnsHostName);
                //if (si.IsEqualDomainSid(domainInfo.DomainSid))
                //{
                //    if (account.EndsWith("\\Exchange Servers", StringComparison.InvariantCultureIgnoreCase)
                //        || account.EndsWith("\\Exchange Recipient administrators", StringComparison.InvariantCultureIgnoreCase)
                //        || account.EndsWith("\\Exchange Trusted Subsystem", StringComparison.InvariantCultureIgnoreCase))
                //    {
                //        continue;
                //    }
                //}

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
                }
            }
        }

        //private void GenerateTopologyData(ADDomainInfo domainInfo, ADWebService adws)
        //{
        //    healthcheckData.SiteTopology = new List<HealthcheckSiteTopologyData>();
        //    string[] properties = new string[] {
        //                "name",
        //                "siteObjectBL",
        //    };
        //    WorkOnReturnedObjectByADWS callback =
        //        (ADItem x) =>
        //        {
        //            HealthcheckSiteTopologyData data = new HealthcheckSiteTopologyData();
        //            healthcheckData.SiteTopology.Add(data);
        //            data.SiteName = x.Name;
        //            data.Subnets = new List<string> ();
        //            foreach(string subnet in x.SiteObjectBL)
        //            {
        //                data.Subnets.Add(GetDisplayName(subnet));
        //            }
        //        };

        //    adws.Enumerate(domainInfo.ConfigurationNamingContext, "(&(ObjectClass=site)(siteObjectBL=*))", properties, callback);
        //}

        private void GenerateGPOData(ADDomainInfo domainInfo, ADWebService adws, NetworkCredential credential)
        {
            healthcheckData.GPPPassword = new List<GPPPassword>();
            healthcheckData.GPPRightAssignment = new List<GPPRightAssignment>();
            healthcheckData.GPPSecurityPolicy = new List<GPPSecurityPolicy>();
            Dictionary<string, string> GPOList = GetGPOList(domainInfo, adws);
            WindowsIdentity identity = null;
            WindowsImpersonationContext context = null;
            string uri = null;
            try
            {
                uri = "\\\\" + domainInfo.DnsHostName + "\\sysvol\\" + domainInfo.DomainName + "\\Policies";
                if (credential != null)
                {
                    identity = NativeMethods.GetWindowsIdentityForUser(credential, domainInfo.DomainName);
                    context = identity.Impersonate();
                }
                

                DirectoryInfo di = new DirectoryInfo(uri);
                DirectoryInfo[] AllDirectories = di.GetDirectories();
                int threadCount = 0;
                ManualResetEvent resetEvent = new ManualResetEvent(false);

                for (int i = 0; i < AllDirectories.Length; i++)
                {
                    DirectoryInfo directoryInfo = AllDirectories[i];
                    string GPOName = "Unknown [" + directoryInfo.Name + "]";
                    if (GPOList.ContainsKey(directoryInfo.Name.ToLower()))
                    {
                        GPOName = GPOList[directoryInfo.Name.ToLower()];
                    }
                    Interlocked.Increment(ref threadCount);
                    ThreadPool.QueueUserWorkItem(
                        o =>
                        {
                            ThreadGPOAnalysis(directoryInfo, GPOName, domainInfo);
                            // We've finished this piece of work...
                            if (Interlocked.Decrement(ref threadCount) == 0)
                            {
                                // ...and we're the last one.
                                // Signal back to the main thread.
                                resetEvent.Set();
                            }
                        }
                        );


                }
                resetEvent.WaitOne();
            }
            catch (UnauthorizedAccessException ex)
            {
                Trace.WriteLine("Exception while generating GPO Data: " + ex.Message);
                Trace.WriteLine(ex.StackTrace);
                lock (Console.Out)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Exception while generating GPO Data: " + ex.Message);
                    Console.ResetColor();
                }
            }
            catch (IOException ex)
            {
                Trace.WriteLine("Exception while generating GPO Data: " + ex.Message);
                Trace.WriteLine(ex.StackTrace);
                lock (Console.Out)
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
                lock (Console.Out)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Exception while generating GPO Data: " + ex.Message);
                    Console.WriteLine(ex.StackTrace);
                    Console.ResetColor();
                }
            }
            finally
            {
                if (context != null)
                    context.Undo();
                if (identity != null)
                    identity.Dispose();
            }
        }

        void ThreadGPOAnalysis(DirectoryInfo directoryInfo, string GPOName, ADDomainInfo domainInfo)
        {
            try
            {
                foreach (FileInfo fi in directoryInfo.GetFiles("*.xml", SearchOption.AllDirectories))
                {
                    ExtractGPPPassword(fi, GPOName);
                }
                foreach (FileInfo fi in directoryInfo.GetFiles("GptTmpl.inf", SearchOption.AllDirectories))
                {
                    ExtractGPPPrivilege(fi, GPOName, domainInfo);
                }
                ExtractGPOLoginScript(directoryInfo, GPOName);

            }
            catch (UnauthorizedAccessException ex)
            {
                lock (Console.Out)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Unable to analyze the GPO: " + directoryInfo.Name + "(" + ex.Message + ")");
                    Console.ResetColor();
                }
            }
            catch (Exception ex)
            {
                lock (Console.Out)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Unable to analyze the GPO: " + directoryInfo.Name + "(" + ex.Message + ")");
                    Console.WriteLine(ex.StackTrace);
                    Console.ResetColor();
                }
            }
        }


        Dictionary<string, string> GetGPOList(ADDomainInfo domainInfo, ADWebService adws)
        {
            Dictionary<string, string> output = new Dictionary<string, string>();
            string[] properties = new string[] {
                        "distinguishedName",
                        "name",
                        "displayName",
            };

            WorkOnReturnedObjectByADWS callback =
                (ADItem x) =>
                {
                    output.Add(x.Name.ToLower(), x.DisplayName);
                };


            adws.Enumerate(domainInfo.DefaultNamingContext, "(objectClass=groupPolicyContainer)", properties, callback);
            return output;
        }

        private void ExtractGPOLoginScript(DirectoryInfo directoryInfo, string GPOName)
        {
            foreach (string gpoType in new[] { "User", "Computer" })
            {
                foreach (string filename in new[] { "scripts.ini", "psscripts.ini" })
                {
                    string path = directoryInfo.FullName + "\\" + gpoType + "\\Scripts\\" + filename;
                    if (File.Exists(path))
                    {
                        ParseGPOLoginScript(path, GPOName, gpoType, filename);
                    }
                }
            }
        }

        private void ParseGPOLoginScript(string path, string GPOName, string gpoType, string filename)
        {
            StreamReader file = new System.IO.StreamReader(path);
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
                        string value = line.Substring(pos + 1);
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
                loginscript.GPOName = GPOName;
                loginscript.Action = "Logoff";
                loginscript.Source = filename;
                loginscript.CommandLine = logonscript[i + "cmdline"];
                if (logonscript.ContainsKey(i + "parameters"))
                {
                    loginscript.Parameters = logonscript[i + "parameters"];
                }
                if (healthcheckData.GPOLoginScript == null)
                    healthcheckData.GPOLoginScript = new List<HealthcheckGPOLoginScriptData>();
                healthcheckData.GPOLoginScript.Add(loginscript);
            }
            for (int i = 0; ; i++)
            {
                if (!logoffscript.ContainsKey(i + "cmdline"))
                {
                    break;
                }
                HealthcheckGPOLoginScriptData loginscript = new HealthcheckGPOLoginScriptData();
                loginscript.GPOName = GPOName;
                loginscript.Action = "Logon";
                loginscript.Source = filename;
                loginscript.CommandLine = logoffscript[i + "cmdline"];
                if (logoffscript.ContainsKey(i + "parameters"))
                {
                    loginscript.Parameters = logoffscript[i + "parameters"];
                }
                if (healthcheckData.GPOLoginScript == null)
                    healthcheckData.GPOLoginScript = new List<HealthcheckGPOLoginScriptData>();
                healthcheckData.GPOLoginScript.Add(loginscript);
            }
        }


        private void ExtractGPPPassword(FileInfo fi, string GPOName)
        {
            string xpath = null;
            switch (fi.Name.ToLower())
            {
                case "groups.xml":
                    xpath = "/Groups/User";
                    break;
                case "services.xml":
                    xpath = "/NTServices/NTService";
                    break;
                case "scheduledtasks.xml":
                    xpath = "/ScheduledTasks/Task";
                    break;
                case "dataSources.xml":
                    xpath = "/DataSources/DataSource";
                    break;
                case "printers.xml":
                    xpath = "/Printers/SharedPrinter";
                    break;
                case "drives.xml":
                    xpath = "/Drives/Drive";
                    break;
                default:
                    return;
            }

            XmlDocument doc = new XmlDocument();
            doc.Load(fi.FullName);
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
                PasswordData.GPOName = GPOName;
                PasswordData.Password = DecodeGPPPassword(password.Value);

                XmlNode accountNameNode = node.SelectSingleNode("Properties/@accountName");
                XmlNode userNameNode = node.SelectSingleNode("Properties/@userName");
                PasswordData.UserName = (accountNameNode != null ? accountNameNode.Value : userNameNode.Value);

                XmlNode changed = node.SelectSingleNode("@changed");
                if (changed != null)
                    PasswordData.Changed = DateTime.Parse(node.SelectSingleNode("@changed").Value);
                else
                    PasswordData.Changed = fi.LastWriteTime;

                XmlNode newNameNode = node.SelectSingleNode("Properties/@newName");
                if (newNameNode != null && !String.IsNullOrEmpty(newNameNode.Value))
                {
                    PasswordData.Other = "NewName:" + newNameNode.Value;
                }
                XmlNode pathNode = node.SelectSingleNode("Properties/@path");
                if (pathNode != null && !String.IsNullOrEmpty(pathNode.Value))
                {
                    PasswordData.Other = "Path:" + pathNode.Value;
                }
                PasswordData.Type = fi.Name.ToLower();

                healthcheckData.GPPPassword.Add(PasswordData);
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
                using (RijndaelManaged aes = new RijndaelManaged())
                {
                    aes.Key = aesKey;
                    aes.IV = new byte[aes.IV.Length];
                    var transform = aes.CreateDecryptor();
                    using (var ms = new MemoryStream())
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

        private void ExtractGPPPrivilege(FileInfo fi, string GPOName, ADDomainInfo domainInfo)
        {
            string[] privileges = new string[] { "SeBackupPrivilege", 
                "SeCreateTokenPrivilege",
                "SeDebugPrivilege", 
                "SeEnableDelegationPrivilege", 
                "SeSyncAgentPrivilege", 
                "SeTakeOwnershipPrivilege",
                "SeTcbPrivilege", 
                "SeTrustedCredManAccessPrivilege",
            };
            string[] PasswordSettings = new string[] {
                "MinimumPasswordAge",
                "MaximumPasswordAge",
                "MinimumPasswordLength",
                "PasswordComplexity",
                "PasswordHistorySize",
                "LockoutBadCount",
                "ResetLockoutCount",
                "LockoutDuration",
                "RequireLogonToChangePassword",
                //"ForceLogoffWhenHourExpire",
                "ClearTextPassword",
            };
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
            };
            GPPSecurityPolicy PSO = null;
            using (StreamReader file = new System.IO.StreamReader(fi.FullName))
            {
                string line;
                while ((line = file.ReadLine()) != null)
                {
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
                                    // ignore empty privilege assignment
                                    if (String.IsNullOrEmpty(user))
                                        continue;
                                    // ignore well known sid
                                    // 
                                    if (user.StartsWith("*S-1-5-32-", StringComparison.InvariantCultureIgnoreCase))
                                    {
                                        continue;
                                    }
                                    // Local system
                                    if (user.StartsWith("*S-1-5-18", StringComparison.InvariantCultureIgnoreCase))
                                    {
                                        continue;
                                    }
                                    GPPRightAssignment right = new GPPRightAssignment();
                                    healthcheckData.GPPRightAssignment.Add(right);
                                    right.GPOName = GPOName;
                                    right.Privilege = privilege;

                                    if (user.StartsWith("*S-1", StringComparison.InvariantCultureIgnoreCase))
                                    {
                                        right.User = NativeMethods.ConvertSIDToName(user.Substring(1), domainInfo.DnsHostName);
                                    }
                                    else
                                    {
                                        right.User = user;
                                    }
                                }

                            }
                        }
                    }
                    if (line.StartsWith(@"MACHINE\System\CurrentControlSet\Control\Lsa\", StringComparison.InvariantCultureIgnoreCase))
                    {
                        int pos = line.IndexOf('=') + 1;
                        if (pos > 1)
                        {
                            string[] values = line.Substring(pos).Split(',');
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
                                        if (lsasetting == "LmCompatibilityLevel" && (value == 3 || value == 5))
                                            continue;
                                        if (lsasetting == "NoLMHash" && value == 1)
                                            continue;
                                        if (lsasetting == "RestrictAnonymous" && value >= 1)
                                            continue;
                                        if (lsasetting == "RestrictAnonymousSAM" && value == 1)
                                            continue;
                                        if (PSO == null)
                                        {
                                            PSO = new GPPSecurityPolicy();
                                            PSO.GPOName = GPOName;
                                            healthcheckData.GPPSecurityPolicy.Add(PSO);
                                            PSO.Properties = new List<GPPSecurityPolicyProperty>();
                                        }
                                        PSO.Properties.Add(new GPPSecurityPolicyProperty(lsasetting, value));
                                    }
                                }
                            }
                        }
                    }
                    foreach (string passwordSetting in PasswordSettings)
                    {
                        if (line.StartsWith(passwordSetting, StringComparison.InvariantCultureIgnoreCase))
                        {
                            int pos = line.IndexOf('=') + 1;
                            if (pos > 1)
                            {
                                if (PSO == null)
                                {
                                    PSO = new GPPSecurityPolicy();
                                    PSO.GPOName = GPOName;
                                    healthcheckData.GPPSecurityPolicy.Add(PSO);
                                    PSO.Properties = new List<GPPSecurityPolicyProperty>();
                                }
                                int value = int.Parse(line.Substring(pos));
                                PSO.Properties.Add(new GPPSecurityPolicyProperty(passwordSetting, value));

                            }
                        }
                    }
                }
            }
        }

        private void GenerateAnomalies(ADDomainInfo domainInfo, ADWebService adws)
        {
            // adding the domain sid
            string[] properties = new string[] {
                        "distinguishedName",
                        "name",
                        "whenCreated",
                        "lastLogonTimestamp",
            };

            List<string> privilegedUser = new List<string>();
            foreach (var member in healthcheckData.AllPrivilegedMembers)
            {
                privilegedUser.Add(member.DistinguishedName);
            }

            healthcheckData.AdminSDHolderNotOK = new List<HealthcheckAccountDetailData>();

            WorkOnReturnedObjectByADWS callbackAdminSDHolder =
                (ADItem x) =>
                {
                    if (!privilegedUser.Contains(x.DistinguishedName))
                    {
                        healthcheckData.AdminSDHolderNotOK.Add(GetAccountDetail(x));
                    }
                };

            adws.Enumerate(domainInfo.DefaultNamingContext, "(&(objectClass=user)(objectCategory=person)(admincount=1)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(sAMAccountName=krbtgt)))", properties, callbackAdminSDHolder);
            healthcheckData.AdminSDHolderNotOKCount = healthcheckData.AdminSDHolderNotOK.Count;

            healthcheckData.SmartCardNotOK = new List<HealthcheckAccountDetailData>();
            WorkOnReturnedObjectByADWS callbackSmartCard =
                (ADItem x) =>
                {
                    healthcheckData.SmartCardNotOK.Add(GetAccountDetail(x));
                };

            adws.Enumerate(domainInfo.DefaultNamingContext, "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(userAccountControl:1.2.840.113556.1.4.803:=262144))", properties, callbackSmartCard);
            healthcheckData.SmartCardNotOKCount = healthcheckData.SmartCardNotOK.Count;
        }



        
    }
}
