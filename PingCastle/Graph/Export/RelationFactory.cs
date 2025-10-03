//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.ADWS;
using PingCastle.Graph.Database;
using PingCastle.misc;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;

namespace PingCastle.Graph.Export
{

    public interface IRelationFactory
    {
        void AnalyzeADObject(ADItem aditem);
        void AnalyzeFile(string fileName);
        void AnalyzeGPO(string fileName);

        void Initialize(IADConnection adws);
        void InitializeDelegation(Dictionary<string, List<string>> delegations, List<string> protocolTransitionSid);
    }

    public class RelationFactory : IRelationFactory
    {

        public IDataStorage Storage { get; set; }
        public ADDomainInfo DomainInfo { get; set; }
        public IADConnection adws { get; set; }

        private List<string> Files = new List<string>();
        private List<string> GPO = new List<string>();

        public RelationFactory(IDataStorage storage, ADDomainInfo domainInfo, IADConnection connection)
        {
            Storage = storage;
            DomainInfo = domainInfo;
            adws = connection;
        }

        public static KeyValuePair<Guid, RelationType>[] GuidsControlExtendedRights = new KeyValuePair<Guid, RelationType>[] {
                    new KeyValuePair<Guid, RelationType>(new Guid("00299570-246d-11d0-a768-00aa006e0529"), RelationType.EXT_RIGHT_FORCE_CHANGE_PWD),
                    new KeyValuePair<Guid, RelationType>(new Guid("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"), RelationType.EXT_RIGHT_REPLICATION_GET_CHANGES_ALL),
                };

        public static KeyValuePair<Guid, RelationType>[] GuidsControlValidatedWrites = new KeyValuePair<Guid, RelationType>[] {
                        new KeyValuePair<Guid, RelationType>(new Guid("bc0ac240-79a9-11d0-9020-00c04fc2d4cf"),RelationType.WRITE_PROPSET_MEMBERSHIP),
                    };

        public static KeyValuePair<Guid, RelationType>[] GuidsControlProperties = new KeyValuePair<Guid, RelationType>[] {
                        new KeyValuePair<Guid, RelationType>(new Guid("bf9679c0-0de6-11d0-a285-00aa003049e2"),RelationType.WRITE_PROP_MEMBER),
                        new KeyValuePair<Guid, RelationType>(new Guid("f30e3bbe-9ff0-11d1-b603-0000f80367c1"),RelationType.WRITE_PROP_GPLINK),
                        new KeyValuePair<Guid, RelationType>(new Guid("f30e3bc1-9ff0-11d0-b603-0000f80367c1"),RelationType.WRITE_PROP_GPC_FILE_SYS_PATH),
                    };
        public static KeyValuePair<Guid, RelationType>[] GuidsControlPropertiesSets = new KeyValuePair<Guid, RelationType>[] {
                        new KeyValuePair<Guid, RelationType>(new Guid("bf9679c0-0de6-11d0-a285-00aa003049e2"),RelationType.VAL_WRITE_SELF_MEMBERSHIP),
                    };

        public List<KeyValuePair<Guid, RelationType>> GuidsReadProperties = new List<KeyValuePair<Guid, RelationType>>();

        public void Initialize(IADConnection adws)
        {
            var lapsAnalyzer = new PingCastle.Healthcheck.LAPSAnalyzer(adws);
            if (lapsAnalyzer.LegacyLAPSSchemaId != Guid.Empty)
                GuidsReadProperties.Add(new KeyValuePair<Guid, RelationType>(lapsAnalyzer.LegacyLAPSSchemaId, RelationType.READ_PROP_MS_MCS_ADMPWD));
            if (lapsAnalyzer.MsLAPSSchemaId != Guid.Empty)
                GuidsReadProperties.Add(new KeyValuePair<Guid, RelationType>(lapsAnalyzer.MsLAPSSchemaId, RelationType.READ_PROP_MS_LAPS_PASSWORD));
            if (lapsAnalyzer.MsLAPSEncryptedSchemaId != Guid.Empty)
                GuidsReadProperties.Add(new KeyValuePair<Guid, RelationType>(lapsAnalyzer.MsLAPSEncryptedSchemaId, RelationType.READ_PROP_MS_LAPS_ENCRYPTED_PASSWORD));
        }

        // mapping from msDS-AllowedToDelegateTo
        Dictionary<string, List<string>> delegations;
        List<string> protocolTransitionSid;

        public void InitializeDelegation(Dictionary<string, List<string>> delegations, List<string> protocolTransitionSid)
        {
            this.delegations = delegations;
            this.protocolTransitionSid = protocolTransitionSid;
        }

        public void AnalyzeADObject(ADItem aditem)
        {
            // avoid reentry which can be caused by primary group id checks
            if (aditem.ObjectSid != null)
            {
                if (Storage.SearchItem(aditem.ObjectSid.Value) != -1)
                {
                    Trace.WriteLine("Item " + aditem.DistinguishedName + " has already been analyzed");
                    return;
                }
            }
            Trace.WriteLine("Working on " + aditem.DistinguishedName);
            Storage.InsertNode(aditem);
            if (String.Equals(aditem.Class, "foreignsecurityprincipal", StringComparison.OrdinalIgnoreCase))
                return;
            // membership, security descriptor, ...
            AddADRelation(aditem);
            // GPO, script
            AddFileRelation(aditem);
        }

        private string SanitizeFileName(string filename, string domainSysVolLocation)
        {
            if (filename.StartsWith("\\\\"))
            {
                return filename;
            }
            else
            {
                return ("\\\\" + DomainInfo.DomainName + "\\sysvol\\" + DomainInfo.DomainName + "\\" + domainSysVolLocation + "\\" + filename).ToLowerInvariant();
            }
        }

        private void AddFileRelation(ADItem aditem)
        {
            if (!String.IsNullOrEmpty(aditem.ScriptPath))
            {
                string file = SanitizeFileName(aditem.ScriptPath, "scripts");
                Storage.InsertRelation(file, MappingType.FileName, aditem.DistinguishedName, MappingType.DistinguishedName, RelationType.scriptPath);
            }
            if (!String.IsNullOrEmpty(aditem.GPCFileSysPath))
            {
                string file = SanitizeFileName(aditem.GPCFileSysPath, "Policies");
                Storage.InsertRelation(file, MappingType.GPODirectory, aditem.DistinguishedName, MappingType.DistinguishedName, RelationType.gPCFileSysPath);
            }
        }

        private void AddADRelation(ADItem aditem)
        {
            if (aditem.DistinguishedName != null && !aditem.DistinguishedName.StartsWith("DC=", StringComparison.OrdinalIgnoreCase))
            {
                string parentcontainer = GetContainerDN(aditem.DistinguishedName);
                Storage.InsertRelation(parentcontainer, MappingType.DistinguishedName, aditem.DistinguishedName, MappingType.DistinguishedName, RelationType.container_hierarchy);
            }
            if (aditem.Member != null)
            {
                foreach (string member in aditem.Member)
                {
                    Storage.InsertRelation(member, MappingType.DistinguishedName, aditem.DistinguishedName, MappingType.DistinguishedName, RelationType.group_member);
                }
            }
            if (aditem.PrimaryGroupID > 0)
            {
                // don't link users with Domain User or Domain Computers ! It will build a complicated graph else
                if (aditem.PrimaryGroupID != 513 && aditem.PrimaryGroupID != 515)
                {
                    Storage.InsertRelation(aditem.DistinguishedName, MappingType.DistinguishedName, DomainInfo.DomainSid + "-" + aditem.PrimaryGroupID, MappingType.Sid, RelationType.primary_group_member);
                }
            }
            if (aditem.NTSecurityDescriptor != null)
            {
                InsertSecurityDescriptorRelation(aditem);
            }
            if (delegations != null)
            {
                List<string> sidDelegated = new List<string>();
                if (!string.IsNullOrEmpty(aditem.DNSHostName) && delegations.ContainsKey(aditem.DNSHostName))
                {
                    foreach (var item in delegations[aditem.DNSHostName])
                    {
                        if (!sidDelegated.Contains(item))
                            sidDelegated.Add(item);
                    }
                }
                if (!string.IsNullOrEmpty(aditem.SAMAccountName) && delegations.ContainsKey(aditem.SAMAccountName.Replace("$", "")))
                {
                    foreach (var item in delegations[aditem.SAMAccountName.Replace("$", "")])
                    {
                        if (!sidDelegated.Contains(item))
                            sidDelegated.Add(item);
                    }
                }
                foreach (var item in sidDelegated)
                {
                    if (protocolTransitionSid.Contains(item))
                    {
                        Storage.InsertRelation(item, MappingType.Sid, aditem.DistinguishedName, MappingType.DistinguishedName, RelationType.msDS_Allowed_To_Delegate_To_With_Protocol_Transition);
                    }
                    else
                    {
                        Storage.InsertRelation(item, MappingType.Sid, aditem.DistinguishedName, MappingType.DistinguishedName, RelationType.msDS_Allowed_To_Delegate_To);
                    }
                }
            }
            if (aditem.msDSAllowedToActOnBehalfOfOtherIdentity != null)
            {
                InsertDelegationRelation(aditem);
            }
            if (!String.IsNullOrEmpty(aditem.GPLink))
            {
                InsertGPORelation(aditem);
            }
            if (aditem.SIDHistory != null)
            {
                foreach (SecurityIdentifier sidHistory in aditem.SIDHistory)
                {
                    Storage.InsertRelation(aditem.DistinguishedName, MappingType.DistinguishedName, sidHistory.Value, MappingType.Sid, RelationType.SIDHistory);
                }
            }
        }

        private void InsertDelegationRelation(ADItem aditem)
        {
            ActiveDirectorySecurity sd = aditem.msDSAllowedToActOnBehalfOfOtherIdentity;
            foreach (ActiveDirectoryAccessRule rule in sd.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                Storage.InsertRelation(((SecurityIdentifier)rule.IdentityReference).Value, MappingType.Sid, aditem.DistinguishedName, MappingType.DistinguishedName, RelationType.msDS_Allowed_To_Act_On_Behalf_Of_Other_Identity);
            }
        }


        // utility fonction to avoid inserting duplicate relations
        private static void IncludeRelationInDictionary(Dictionary<string, List<RelationType>> relationToAdd, string targetsid, RelationType relationType)
        {
            if (!relationToAdd.ContainsKey(targetsid))
            {
                relationToAdd[targetsid] = new List<RelationType>();
            }
            if (!relationToAdd[targetsid].Contains(relationType))
            {
                relationToAdd[targetsid].Add(relationType);
            }
        }

        Guid userGuid = new Guid("bf967aba-0de6-11d0-a285-00aa003049e2");
        Guid computerGuid = new Guid("bf967a86-0de6-11d0-a285-00aa003049e2");
        Guid OUGuid = new Guid("bf967aa5-0de6-11d0-a285-00aa003049e2");
        Guid groupGuid = new Guid("bf967a9c-0de6-11d0-a285-00aa003049e2");
        Guid inetOrgGuid = new Guid("4828cc14-1437-45bc-9b07-ad6f015e5f28");
        Guid mSAGuid = new Guid("ce206244-5827-4a86-ba1c-1c0c386c1b64");
        Guid gMSAGuid = new Guid("7b8b558a-93a5-4af7-adca-c017e67f1057");

        private void InsertSecurityDescriptorRelation(ADItem aditem)
        {

            ActiveDirectorySecurity sd = aditem.NTSecurityDescriptor;
            Storage.InsertRelation(sd.GetOwner(typeof(SecurityIdentifier)).Value, MappingType.Sid, aditem.DistinguishedName, MappingType.DistinguishedName, RelationType.AD_OWNER);
            // relations can be duplicated - will slow down import 
            Dictionary<string, List<RelationType>> relationToAdd = new Dictionary<string, List<RelationType>>();

            foreach (ActiveDirectoryAccessRule accessrule in sd.GetAccessRules(true, false, typeof(SecurityIdentifier)))
            {
                // ignore audit / denied ace
                if (accessrule.AccessControlType != AccessControlType.Allow)
                    continue;

                RelationType restrictedObject = RelationType.container_hierarchy;

                if ((accessrule.ObjectFlags & ObjectAceFlags.ObjectAceTypePresent) != 0)
                {
                    restrictedObject = GetRestrictedToRelation(accessrule.ObjectType.ToString().ToLowerInvariant());
                    if (restrictedObject == RelationType.container_hierarchy)
                    {
                        continue;
                    }
                }
                if ((accessrule.ObjectFlags & ObjectAceFlags.InheritedObjectAceTypePresent) != 0)
                {
                    restrictedObject = GetRestrictedToRelation(accessrule.InheritedObjectType.ToString().ToLowerInvariant());
                    if (restrictedObject == RelationType.container_hierarchy)
                    {
                        continue;
                    }
                }

                bool set = false;
                // ADS_RIGHT_GENERIC_ALL
                if (IsRightSetinAccessRule(accessrule, ActiveDirectoryRights.GenericAll))
                {
                    IncludeRelationInDictionary(relationToAdd, accessrule.IdentityReference.Value, RelationType.GEN_RIGHT_ALL);
                    set = true;
                }
                else
                {
                    // ADS_RIGHT_GENERIC_WRITE
                    if (IsRightSetinAccessRule(accessrule, ActiveDirectoryRights.GenericWrite))
                    {
                        IncludeRelationInDictionary(relationToAdd, accessrule.IdentityReference.Value, RelationType.GEN_RIGHT_WRITE);
                        set = true;
                    }
                    // ADS_RIGHT_WRITE_DAC
                    if (IsRightSetinAccessRule(accessrule, ActiveDirectoryRights.WriteDacl))
                    {
                        IncludeRelationInDictionary(relationToAdd, accessrule.IdentityReference.Value, RelationType.ADS_RIGHT_WRITE_DAC);
                        set = true;
                    }
                    // ADS_RIGHT_WRITE_OWNER
                    if (IsRightSetinAccessRule(accessrule, ActiveDirectoryRights.WriteOwner))
                    {
                        IncludeRelationInDictionary(relationToAdd, accessrule.IdentityReference.Value, RelationType.ADS_RIGHT_WRITE_OWNER);
                        set = true;
                    }
                    if (accessrule.ObjectFlags == ObjectAceFlags.None)
                    {
                        // ADS_RIGHT_DS_CONTROL_ACCESS
                        if (IsRightSetinAccessRule(accessrule, ActiveDirectoryRights.ExtendedRight))
                        {
                            IncludeRelationInDictionary(relationToAdd, accessrule.IdentityReference.Value, RelationType.EXT_RIGHT_ALL);
                            set = true;
                        }
                        // ADS_RIGHT_DS_SELF
                        if (IsRightSetinAccessRule(accessrule, ActiveDirectoryRights.Self))
                        {
                            IncludeRelationInDictionary(relationToAdd, accessrule.IdentityReference.Value, RelationType.VAL_WRITE_ALL);
                            set = true;
                        }
                        // ADS_RIGHT_DS_WRITE_PROP
                        if (IsRightSetinAccessRule(accessrule, ActiveDirectoryRights.WriteProperty))
                        {
                            IncludeRelationInDictionary(relationToAdd, accessrule.IdentityReference.Value, RelationType.WRITE_PROP_ALL);
                            set = true;
                        }
                    }
                    else if ((accessrule.ObjectFlags & ObjectAceFlags.ObjectAceTypePresent) == ObjectAceFlags.ObjectAceTypePresent)
                    {
                        // ADS_RIGHT_DS_CONTROL_ACCESS
                        if (IsRightSetinAccessRule(accessrule, ActiveDirectoryRights.ExtendedRight))
                        {
                            foreach (KeyValuePair<Guid, RelationType> extendedright in GuidsControlExtendedRights)
                            {
                                if (extendedright.Key == accessrule.ObjectType)
                                {
                                    IncludeRelationInDictionary(relationToAdd, accessrule.IdentityReference.Value, extendedright.Value);
                                    set = true;
                                }
                            }
                        }
                        // ADS_RIGHT_DS_SELF
                        if (IsRightSetinAccessRule(accessrule, ActiveDirectoryRights.Self))
                        {
                            foreach (KeyValuePair<Guid, RelationType> validatewrite in GuidsControlValidatedWrites)
                            {
                                if (validatewrite.Key == accessrule.ObjectType)
                                {
                                    IncludeRelationInDictionary(relationToAdd, accessrule.IdentityReference.Value, validatewrite.Value);
                                    set = true;
                                }
                            }
                        }
                        // ADS_RIGHT_DS_WRITE_PROP
                        if (IsRightSetinAccessRule(accessrule, ActiveDirectoryRights.WriteProperty))
                        {
                            foreach (KeyValuePair<Guid, RelationType> controlproperty in GuidsControlProperties)
                            {
                                if (controlproperty.Key == accessrule.ObjectType)
                                {
                                    IncludeRelationInDictionary(relationToAdd, accessrule.IdentityReference.Value, controlproperty.Value);
                                    set = true;
                                }
                            }
                            foreach (KeyValuePair<Guid, RelationType> controlpropertyset in GuidsControlPropertiesSets)
                            {
                                if (controlpropertyset.Key == accessrule.ObjectType)
                                {
                                    IncludeRelationInDictionary(relationToAdd, accessrule.IdentityReference.Value, controlpropertyset.Value);
                                    set = true;
                                }
                            }
                        }
                        if (IsRightSetinAccessRule(accessrule, ActiveDirectoryRights.ReadProperty))
                        {
                            foreach (KeyValuePair<Guid, RelationType> controlproperty in GuidsReadProperties)
                            {
                                if (controlproperty.Key == accessrule.ObjectType)
                                {
                                    IncludeRelationInDictionary(relationToAdd, accessrule.IdentityReference.Value, controlproperty.Value);
                                    set = true;
                                }
                            }
                        }
                    }
                }
                if (set && restrictedObject != RelationType.container_hierarchy && relationToAdd.ContainsKey(accessrule.IdentityReference.Value))
                {
                    IncludeRelationInDictionary(relationToAdd, accessrule.IdentityReference.Value, restrictedObject);
                }
            }
            foreach (string target in relationToAdd.Keys)
            {
                foreach (RelationType link in relationToAdd[target])
                {
                    Storage.InsertRelation(target, MappingType.Sid, aditem.DistinguishedName, MappingType.DistinguishedName, link);
                }
            }
        }

        public static RelationType GetRestrictedToRelation(string objectType)
        {
            switch (objectType)
            {
                case "4828cc14-1437-45bc-9b07-ad6f015e5f28": // inetorg
                case "bf967aba-0de6-11d0-a285-00aa003049e2": // user
                    return RelationType.RestrictedToUser;
                case "bf967a86-0de6-11d0-a285-00aa003049e2":
                    return RelationType.RestrictedToComputer;
                case "bf967aa5-0de6-11d0-a285-00aa003049e2":
                    return RelationType.RestrictedToOU;
                case "bf967a9c-0de6-11d0-a285-00aa003049e2":
                    return RelationType.RestrictedToGroup;
                case "ce206244-5827-4a86-ba1c-1c0c386c1b64":
                case "7b8b558a-93a5-4af7-adca-c017e67f1057":
                    return RelationType.RestrictedToMsaOrGmsa;
                case "f30e3bc2-9ff0-11d1-b603-0000f80367c1":
                    return RelationType.RestrictedToGpo;
                default:
                    return RelationType.container_hierarchy;
            }
        }

        private void InsertGPORelation(ADItem aditem)
        {
            foreach (string dn in aditem.GetApplicableGPO())
            {
                Storage.InsertRelation(dn, MappingType.DistinguishedName, aditem.DistinguishedName, MappingType.DistinguishedName, RelationType.GPLINK);
            }
        }


        // from a DN string, get the parent. 
        // the problem is that there can be dn with escape string
        // example: "CN=John\, Doe,OU=My OU,DC=domain,DC=com"

        Regex re = new Regex(@"^(?:OU|CN)=(?<cn>.+?)(?<!\\),(?<ou>(?:(?:OU|CN).+?(?<!\\),)*(?<dc>DC.+?))$");

        private string GetContainerDN(string dn)
        {
            Match m = re.Match(dn);
            if (!m.Success)
                return String.Empty;
            return m.Groups[2].Value;
        }

        public void AnalyzeFile(string fileName)
        {
            Trace.WriteLine("working on filenode=" + fileName);
            try
            {
                Storage.InsertFileNode(fileName);

                // when connecting a login password, unc path starting the with domain name (<> domain controller) fails
                // rebuild it by replacing the domain name by the domain controller name
                Uri uri;
                if (!Uri.TryCreate(fileName, UriKind.RelativeOrAbsolute, out uri))
                {
                    Trace.WriteLine("Unable to parse the url: " + fileName);
                    return;
                }
                if (!uri.IsUnc)
                {
                    Trace.WriteLine("File " + fileName + " is not a unc path");
                    return;
                }

                // SYSVOL volume cannot be accessed with login / password login
                // in this case, the server (aka the domain) needs to be replaced with the FQDN of the server
                if (uri.Host.Equals(DomainInfo.DomainName, StringComparison.OrdinalIgnoreCase))
                {
                    UriBuilder builder = new UriBuilder(uri);
                    builder.Host = DomainInfo.DnsHostName;
                    uri = builder.Uri;
                    Trace.WriteLine("Change " + fileName + " by " + uri.LocalPath);
                }
                string alternativeFilepath = uri.LocalPath;

                FileSystemSecurity fss = null;
                // insert relation related to security descriptor
                if (adws.FileConnection.IsDirectory(alternativeFilepath))
                {
                    fss = adws.FileConnection.GetDirectorySecurity(alternativeFilepath);
                }
                else
                {
                    fss = adws.FileConnection.GetFileSecurity(alternativeFilepath);
                }
                InsertFileDescriptorRelation(fileName, fss, false, null, fileName, MappingType.FileName);
            }
            catch (UnauthorizedAccessException)
            {
                Trace.WriteLine("Access denied for " + fileName);
            }
            catch (Exception ex)
            {
                Trace.WriteLine("An exception occured while working on the file '" + fileName + "':" + ex.Message);
            }
        }

        private delegate void ProcessGPOItem(string gpoPath, string applyTo, string artefactPath);

        public void AnalyzeGPO(string gpoPath)
        {
            Storage.InsertGPONode(gpoPath);
            try
            {
                // analyse SD of files in directory
                if (!adws.FileConnection.DirectoryExists(gpoPath))
                    return;
                // is the subdirectory an inheritage ?
                InsertFileDescriptorRelation(gpoPath, adws.FileConnection.GetDirectorySecurity(gpoPath), false, null, gpoPath, MappingType.GPODirectory);

                foreach (string applyTo in new[] { "Machine", "User" })
                {
                    foreach (string scriptconfig in new[] { "scripts.ini", "psscripts.ini" })
                    {
                        AnalyzeGPOItem(adws, gpoPath, applyTo, "Scripts\\" + scriptconfig, "Configuration file defining login/logoff scripts", AnalyzeLoginLogoffScript);
                    }
                    if (string.Equals(applyTo, "Machine"))
                    {
                        AnalyzeGPOItem(adws, gpoPath, applyTo, "Microsoft\\Windows nt\\SecEdit\\GptTmpl.inf", "Configuration file defining local privileges", AnalyseGPTINI);
                    }
                    AnalyzeGPOItem(adws, gpoPath, applyTo, "Registry.pol", "Configuration file whose settings are copied to the registry", null);
                }
                // TODO: msi !!!
            }
            catch (UnauthorizedAccessException)
            {
                Trace.WriteLine("Access denied for " + gpoPath);
            }
            catch (System.IO.DirectoryNotFoundException)
            {
                Trace.WriteLine("Path not found for " + gpoPath);
            }
            catch (Exception)
            {
                Trace.WriteLine("An error occured while processing the GPO: " + gpoPath);
                throw;
            }
        }

        private void AnalyzeGPOItem(IADConnection adws, string gpoPath, string applyTo, string artefactPath, string artefactDescription, ProcessGPOItem processGPOItem)
        {
            string path = adws.FileConnection.PathCombine(adws.FileConnection.PathCombine(gpoPath, applyTo), artefactPath);
            try
            {

                var PathFragment = artefactPath.Split(new char[] { '\\', '/' });
                string dirpath = adws.FileConnection.PathCombine(gpoPath, applyTo);
                Dictionary<string, List<RelationType>> relationToAdd = null;
                for (int i = 0; i < PathFragment.Length; i++)
                {
                    dirpath = adws.FileConnection.PathCombine(dirpath, PathFragment[i]);
                    FileSystemSecurity fs = null;
                    if (i == PathFragment.Length - 1)
                    {
                        if (adws.FileConnection.FileExists(dirpath))
                        {
                            fs = adws.FileConnection.GetFileSecurity(dirpath);
                        }
                        else
                        {
                            break;
                        }
                    }
                    else
                    {
                        try
                        {
                            fs = adws.FileConnection.GetDirectorySecurity(dirpath);
                        }
                        catch
                        {
                            break;
                        }
                    }
                    var o = AnalyzeFileSecurityDescriptor(dirpath, fs, true);
                    if (relationToAdd == null)
                        relationToAdd = o;
                    else
                        relationToAdd = CombineSDAnalysis(relationToAdd, o);
                }
                if (relationToAdd != null)
                {
                    foreach (string target in relationToAdd.Keys)
                    {
                        foreach (RelationType link in relationToAdd[target])
                        {
                            {
                                Storage.InsertRelation(target, MappingType.Sid, path, MappingType.FileName, link);
                            }
                        }
                    }
                }

                if (adws.FileConnection.FileExists(path))
                {

                    Storage.InsertFileNode(path, artefactDescription);
                    Storage.InsertRelation(path, MappingType.FileName, gpoPath, MappingType.GPODirectory, RelationType.container_hierarchy);
                    if (processGPOItem != null)
                    {
                        processGPOItem(gpoPath, applyTo, artefactPath);
                    }
                }
            }
            catch (UnauthorizedAccessException)
            {
                Trace.WriteLine("Access denied for " + path);
            }
            catch (Exception ex)
            {
                Trace.WriteLine("Exception " + ex.Message + " for " + path);
                Trace.WriteLine(ex.StackTrace);
            }
        }

        private void AnalyzeLoginLogoffScript(string gpoPath, string applyTo, string artefactPath)
        {
            string configPath = gpoPath + "\\" + applyTo + "\\" + artefactPath;
            using (var file2 = adws.FileConnection.GetFileStream(configPath))
            using (var file = new System.IO.StreamReader(file2))
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
                    AnalyzeScript(configPath, logonscript[i + "cmdline"], (string.Equals(applyTo, "Machine", StringComparison.InvariantCultureIgnoreCase) ? RelationType.Startup_Script : RelationType.Logon_Script));

                }
                for (int i = 0; ; i++)
                {
                    if (!logoffscript.ContainsKey(i + "cmdline"))
                    {
                        break;
                    }
                    AnalyzeScript(configPath, logoffscript[i + "cmdline"], (string.Equals(applyTo, "Machine", StringComparison.InvariantCultureIgnoreCase) ? RelationType.ShutdownScript : RelationType.Logoff_Script));
                }
            }
        }

        private void AnalyzeScript(string filenode, string script, RelationType relationType)
        {
            if (!script.Contains("\\"))
                return;
            if (!script.StartsWith("\\\\"))
                return;
            try
            {
                Storage.InsertFileNode(script);
                if (adws.FileConnection.FileExists(script))
                {
                    FileSecurity fss = adws.FileConnection.GetFileSecurity(script);
                    Storage.InsertRelation(script, MappingType.FileName, filenode, MappingType.FileName, relationType);
                    InsertFileDescriptorRelation(script, fss, false, null, script, MappingType.FileName);
                }
            }
            catch (Exception)
            {
                Trace.WriteLine("Exception while analyzing : " + script);
            }
        }

        private void AnalyseGPTINI(string gpoPath, string applyTo, string artefactPath)
        {
            RelationType[] privileges = new RelationType[] {
                RelationType.SeBackupPrivilege,
                RelationType.SeCreateTokenPrivilege,
                RelationType.SeDebugPrivilege,
                RelationType.SeTakeOwnershipPrivilege,
                RelationType.SeTcbPrivilege,
            };
            string path = gpoPath + "\\" + applyTo + "\\" + artefactPath;
            if (adws.FileConnection.FileExists(path))
            {
                using (var file2 = adws.FileConnection.GetFileStream(path))
                using (var file = new System.IO.StreamReader(file2))
                {
                    string line;
                    while ((line = file.ReadLine()) != null)
                    {
                        foreach (RelationType privilege in privileges)
                        {
                            if (line.StartsWith(privilege.ToString(), StringComparison.InvariantCultureIgnoreCase))
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
                                        if (user.StartsWith("*S-1", StringComparison.InvariantCultureIgnoreCase))
                                        {
                                            Storage.InsertRelation(user.Substring(1), MappingType.Sid, gpoPath, MappingType.FileName, privilege);
                                        }
                                        else
                                        {
                                            Storage.InsertRelation(user, MappingType.DistinguishedName, gpoPath, MappingType.FileName, privilege);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }


        private void AnalyzeRegistryPol(string gpoPath, string applyTo, string artefactPath)
        {
            string configPath = gpoPath + "\\" + applyTo + "\\" + artefactPath;
            RegistryPolReader reader = new RegistryPolReader(adws.FileConnection);
            reader.LoadFile(configPath);
            foreach (RegistryPolRecord record in reader.SearchRecord(@"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"))
            {
                if (record.Value == "**delvals.")
                    continue;
                string filename = Encoding.Unicode.GetString(record.ByteValue).Trim();
                if (string.IsNullOrEmpty(filename))
                    continue;
                filename = filename.Replace("\0", string.Empty);
                // this is bad, I'm assuming that the file name doesn't contain any space which is wrong.
                // but a real command line parsing will bring more anomalies.
                var filePart = filename.Split(' ');
                if (filePart[0].StartsWith("\\\\"))
                {
                    FileSecurity fss = adws.FileConnection.GetFileSecurity(filePart[0]);
                    Storage.InsertFileNode(filePart[0]);
                    Storage.InsertRelation(filePart[0], MappingType.FileName, configPath, MappingType.FileName, (string.Equals(applyTo, "Machine", StringComparison.InvariantCultureIgnoreCase) ? RelationType.Startup_Script : RelationType.Logon_Script));
                    InsertFileDescriptorRelation(filePart[0], fss, false, null, filePart[0], MappingType.FileName);
                }
            }
        }

        // return true if there is new relation(s) created
        private bool InsertFileDescriptorRelation(string filepath, FileSystemSecurity sd, bool skipInherited, string knownOwner, string node, MappingType nodeType)
        {
            bool newRelation = false;
            var relationToAdd = AnalyzeFileSecurityDescriptor(filepath, sd, skipInherited);
            foreach (string target in relationToAdd.Keys)
            {
                foreach (RelationType link in relationToAdd[target])
                {
                    if (!(link == RelationType.FILE_OWNER && string.Equals(target, knownOwner, StringComparison.InvariantCultureIgnoreCase)))
                    {
                        Storage.InsertRelation(target, MappingType.Sid, node, nodeType, link);
                        newRelation = true;
                    }
                }
            }
            return newRelation;
        }

        Dictionary<string, List<RelationType>> CombineSDAnalysis(Dictionary<string, List<RelationType>> input1, Dictionary<string, List<RelationType>> input2)
        {
            Dictionary<string, List<RelationType>> relationToAdd = new Dictionary<string, List<RelationType>>();
            foreach (var key in input1.Keys)
            {
                if (!relationToAdd.ContainsKey(key))
                    relationToAdd[key] = new List<RelationType>();
                relationToAdd[key].AddRange(input1[key]);
            }
            foreach (var key in input2.Keys)
            {
                if (!relationToAdd.ContainsKey(key))
                    relationToAdd[key] = new List<RelationType>();
                foreach (var t in input2[key])
                {
                    if (!relationToAdd[key].Contains(t))
                        relationToAdd[key].Add(t);
                }
            }
            return relationToAdd;
        }

        private Dictionary<string, List<RelationType>> AnalyzeFileSecurityDescriptor(string filepath, FileSystemSecurity sd, bool skipInherited)
        {
            // relations can be duplicated - will slow down import 
            Dictionary<string, List<RelationType>> relationToAdd = new Dictionary<string, List<RelationType>>();
            Storage.InsertRelation(sd.GetOwner(typeof(SecurityIdentifier)).Value, MappingType.Sid, filepath, MappingType.FileName, RelationType.FILE_OWNER);
            foreach (FileSystemAccessRule accessrule in sd.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                // ignore audit / denied ace
                if (accessrule.AccessControlType != AccessControlType.Allow)
                    continue;

                if (skipInherited && accessrule.IsInherited)
                    continue;

                // GEN_RIGHT_ALL
                if (IsRightSetinAccessRule(accessrule, FileSystemRights.FullControl))
                {
                    IncludeRelationInDictionary(relationToAdd, accessrule.IdentityReference.Value, RelationType.GEN_RIGHT_ALL);
                }
                else
                {
                    // GEN_RIGHT_WRITE
                    if (IsRightSetinAccessRule(accessrule, FileSystemRights.Write))
                    {
                        IncludeRelationInDictionary(relationToAdd, accessrule.IdentityReference.Value, RelationType.GEN_RIGHT_WRITE);
                    }
                    // STAND_RIGHT_WRITE_DAC
                    if (IsRightSetinAccessRule(accessrule, FileSystemRights.ChangePermissions))
                    {
                        IncludeRelationInDictionary(relationToAdd, accessrule.IdentityReference.Value, RelationType.STAND_RIGHT_WRITE_DAC);
                    }
                    // STAND_RIGHT_WRITE_OWNER
                    if (IsRightSetinAccessRule(accessrule, FileSystemRights.TakeOwnership))
                    {
                        IncludeRelationInDictionary(relationToAdd, accessrule.IdentityReference.Value, RelationType.STAND_RIGHT_WRITE_OWNER);
                    }
                    // FILE_WRITEDATA_ADDFILE
                    if (IsRightSetinAccessRule(accessrule, FileSystemRights.WriteData))
                    {
                        IncludeRelationInDictionary(relationToAdd, accessrule.IdentityReference.Value, RelationType.FS_RIGHT_WRITEDATA_ADDFILE);
                    }
                    // FILE_APPENDDATA_ADDSUBDIR
                    if (IsRightSetinAccessRule(accessrule, FileSystemRights.AppendData))
                    {
                        IncludeRelationInDictionary(relationToAdd, accessrule.IdentityReference.Value, RelationType.FS_RIGHT_APPENDDATA_ADDSUBDIR);
                    }
                }
            }
            return relationToAdd;
        }

        private static bool IsRightSetinAccessRule(ActiveDirectoryAccessRule accessrule, ActiveDirectoryRights right)
        {
            return (accessrule.ActiveDirectoryRights & right) == right;
        }

        private static bool IsRightSetinAccessRule(FileSystemAccessRule accessrule, FileSystemRights right)
        {
            return (accessrule.FileSystemRights & right) == right;
        }
    }

}
