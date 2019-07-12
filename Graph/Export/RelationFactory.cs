//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.ADWS;
using PingCastle.Graph.Database;
using PingCastle.Graph.Export;
using PingCastle.misc;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.DirectoryServices;
using System.IO;
using System.Net;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace PingCastle.Graph.Export
{

    public class RelationFactory : IRelationFactory
    {

        public IDataStorage Storage { get; set; }
        public ADDomainInfo DomainInfo { get; set; }

        private List<string> Files = new List<string>();
        private List<string> GPO = new List<string>();

        public RelationFactory(IDataStorage storage, ADDomainInfo domainInfo)
        {
            Storage = storage;
            DomainInfo = domainInfo;
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
			string[] propertiesLaps = new string[] { "schemaIDGUID" };
			// note: the LDAP request does not contain ms-MCS-AdmPwd because in the old time, MS consultant was installing customized version of the attriute, * being replaced by the company name
			// check the oid instead ? (which was the same even if the attribute name was not)
			adws.Enumerate(DomainInfo.SchemaNamingContext, "(name=ms-*-AdmPwd)", propertiesLaps, (ADItem aditem) => {
				GuidsReadProperties.Add(new KeyValuePair<Guid,RelationType>(aditem.SchemaIDGUID, RelationType.READ_PROP_MS_MCS_ADMPWD));
			}, "OneLevel");
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
            InsertNode(aditem);
			if (String.Equals(aditem.Class, "foreignsecurityprincipal", StringComparison.OrdinalIgnoreCase))
				return;
            // membership, security descriptor, ...
            AddADRelation(aditem);
            // GPO, script
            AddFileRelation(aditem);
        }

        private void InsertNode(ADItem aditem)
        {
            string shortname = aditem.DisplayName;
			if (String.IsNullOrEmpty(shortname))
			{
				shortname = aditem.Name;
			}
            //if (aditem.Class.Equals("foreignSecurityPrincipal", StringComparison.InvariantCultureIgnoreCase) && aditem.ObjectSid != null)
            //{
            //    shortname = NativeMethods.ConvertSIDToName(aditem.ObjectSid.Value, null);
            //}
            if (String.IsNullOrEmpty(shortname))
            {
                Regex re = new Regex(@"^(?:OU|CN)=(?<cn>.+?)(?<!\\),(?<ou>(?:(?:OU|CN).+?(?<!\\),)*(?<dc>DC.+?))$");
                Match m = re.Match(aditem.DistinguishedName);
                if (!m.Success)
                    shortname = "<none>";
                else
                    shortname = m.Groups[1].Value;
            }
            Storage.InsertNode(shortname, aditem.Class.ToLowerInvariant(), aditem.DistinguishedName, (aditem.ObjectSid != null ? aditem.ObjectSid.Value : null), aditem);
        }

        private void InsertFileNode(string fileName)
        {
			Storage.InsertNode(fileName, "file", fileName, null, null);
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
                Storage.InsertRelation(file, MappingType.Name, aditem.DistinguishedName, MappingType.Name, RelationType.scriptPath);
            } 
            if (!String.IsNullOrEmpty(aditem.GPCFileSysPath))
            {
                string file = SanitizeFileName(aditem.GPCFileSysPath, "Policies");
                Storage.InsertRelation(file, MappingType.Name, aditem.DistinguishedName, MappingType.Name, RelationType.gPCFileSysPath);
            }
        }

        private void AddADRelation(ADItem aditem)
        {
            if (aditem.DistinguishedName != null && !aditem.DistinguishedName.StartsWith("DC=", StringComparison.OrdinalIgnoreCase))
            {
                string parentcontainer = GetContainerDN(aditem.DistinguishedName);
                Storage.InsertRelation(parentcontainer, MappingType.Name, aditem.DistinguishedName, MappingType.Name, RelationType.container_hierarchy);
            }
            if (aditem.MemberOf != null)
            {
                foreach (string member in aditem.MemberOf)
                {
                    Storage.InsertRelation(aditem.DistinguishedName, MappingType.Name, member, MappingType.Name, RelationType.group_member);
                }
            }
            if (aditem.Member != null)
            {
                foreach (string member in aditem.Member)
                {
                    Storage.InsertRelation(member, MappingType.Name, aditem.DistinguishedName, MappingType.Name, RelationType.group_member);
                }
            }
            if (aditem.PrimaryGroupID > 0)
            {
                Storage.InsertRelation(aditem.DistinguishedName, MappingType.Name, DomainInfo.DomainSid + "-" + aditem.PrimaryGroupID, MappingType.Sid, RelationType.primary_group_member);
            }
            if (aditem.NTSecurityDescriptor != null)
            {
                InsertSecurityDescriptorRelation(aditem);
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
                    Storage.InsertRelation(aditem.DistinguishedName, MappingType.Name, sidHistory.Value, MappingType.Sid, RelationType.SIDHistory);
                }
            }
        }

		private void InsertDelegationRelation(ADItem aditem)
		{
			ActiveDirectorySecurity sd = aditem.msDSAllowedToActOnBehalfOfOtherIdentity;
			foreach (ActiveDirectoryAccessRule rule in sd.GetAccessRules(true, true, typeof(SecurityIdentifier)))
			{
				Storage.InsertRelation(((SecurityIdentifier)rule.IdentityReference).Value, MappingType.Sid, aditem.DistinguishedName, MappingType.Name, RelationType.msDSAllowedToActOnBehalfOfOtherIdentity);
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

        private void InsertSecurityDescriptorRelation(ADItem aditem)
        {

            ActiveDirectorySecurity sd = aditem.NTSecurityDescriptor;
            Storage.InsertRelation(sd.GetOwner(typeof(SecurityIdentifier)).Value, MappingType.Sid, aditem.DistinguishedName, MappingType.Name, RelationType.AD_OWNER);
            // relations can be duplicated - will slow down import 
            Dictionary<string, List<RelationType>> relationToAdd = new Dictionary<string, List<RelationType>>();

            foreach (ActiveDirectoryAccessRule accessrule in sd.GetAccessRules(true, false, typeof(SecurityIdentifier)))
            {
                // ignore audit / denied ace
                if (accessrule.AccessControlType != AccessControlType.Allow)
                    continue;

                // ADS_RIGHT_GENERIC_ALL
                if (IsRightSetinAccessRule(accessrule, ActiveDirectoryRights.GenericAll))
                {
                    IncludeRelationInDictionary(relationToAdd, accessrule.IdentityReference.Value, RelationType.GEN_RIGHT_ALL);
                }
                else
                {
                    // ADS_RIGHT_GENERIC_WRITE
                    if (IsRightSetinAccessRule(accessrule, ActiveDirectoryRights.GenericWrite))
                    {
                        IncludeRelationInDictionary(relationToAdd, accessrule.IdentityReference.Value, RelationType.GEN_RIGHT_WRITE);
                    }
                    // ADS_RIGHT_WRITE_DAC
                    if (IsRightSetinAccessRule(accessrule, ActiveDirectoryRights.WriteDacl))
                    {
                        IncludeRelationInDictionary(relationToAdd, accessrule.IdentityReference.Value, RelationType.ADS_RIGHT_WRITE_DAC);
                    }
                    // ADS_RIGHT_WRITE_OWNER
                    if (IsRightSetinAccessRule(accessrule, ActiveDirectoryRights.WriteOwner))
                    {
                        IncludeRelationInDictionary(relationToAdd, accessrule.IdentityReference.Value, RelationType.ADS_RIGHT_WRITE_OWNER);
                    }
                    if (accessrule.ObjectFlags == ObjectAceFlags.None)
                    {
                        // ADS_RIGHT_DS_CONTROL_ACCESS
                        if (IsRightSetinAccessRule(accessrule, ActiveDirectoryRights.ExtendedRight))
                        {
                            IncludeRelationInDictionary(relationToAdd, accessrule.IdentityReference.Value, RelationType.EXT_RIGHT_ALL);
                        }
                        // ADS_RIGHT_DS_SELF
                        if (IsRightSetinAccessRule(accessrule, ActiveDirectoryRights.Self))
                        {
                            IncludeRelationInDictionary(relationToAdd, accessrule.IdentityReference.Value, RelationType.VAL_WRITE_ALL);
                        }
                        // ADS_RIGHT_DS_WRITE_PROP
                        if (IsRightSetinAccessRule(accessrule, ActiveDirectoryRights.WriteProperty))
                        {
                            IncludeRelationInDictionary(relationToAdd, accessrule.IdentityReference.Value, RelationType.WRITE_PROP_ALL);
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
                                }
                            }
                            foreach (KeyValuePair<Guid, RelationType> controlpropertyset in GuidsControlPropertiesSets)
                            {
                                if (controlpropertyset.Key == accessrule.ObjectType)
                                {
                                    IncludeRelationInDictionary(relationToAdd, accessrule.IdentityReference.Value, controlpropertyset.Value);
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
								}
							}
						}
                    }
                }
            }
            foreach (string target in relationToAdd.Keys)
            {
                foreach (RelationType link in relationToAdd[target])
                {
                    Storage.InsertRelation(target, MappingType.Sid, aditem.DistinguishedName, MappingType.Name, link);
                }
            }
        }


        private void InsertGPORelation(ADItem aditem)
        {
            string[] gplinks = aditem.GPLink.Split(']');
            foreach (string gplink in gplinks)
            {
                if (String.IsNullOrEmpty(gplink.TrimEnd()))
                    continue;
                string[] gpodata = gplink.Split(';');
                if (gpodata.Length != 2)
                {
                    Trace.WriteLine("invalid gpolink1:" + gplink);
                    continue;
                }
                int flag = int.Parse(gpodata[1]);
                if ( flag == 1) 
                    continue;
                if (!gpodata[0].StartsWith("[LDAP://", StringComparison.InvariantCultureIgnoreCase))
                {
                    Trace.WriteLine("invalid gpolink2:" + gplink);
                    continue;
                }
                string dn = gpodata[0].Substring(8);
                Storage.InsertRelation(dn, MappingType.Name, aditem.DistinguishedName, MappingType.Name, RelationType.GPLINK);
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
                InsertFileNode(fileName);

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
                if (uri.Host.Equals(DomainInfo.DomainName, StringComparison.InvariantCultureIgnoreCase))
                {
                    UriBuilder builder = new UriBuilder(uri);
                    builder.Host = DomainInfo.DnsHostName;
                    uri = builder.Uri;
                }
                string alternativeFilepath = uri.LocalPath;

                FileSystemInfo info = null;
                FileAttributes attr = File.GetAttributes(alternativeFilepath);
                FileSystemSecurity fss = null;
                // insert relation related to security descriptor
                if ((attr & FileAttributes.Directory) == FileAttributes.Directory)
                {
                    info = new DirectoryInfo(alternativeFilepath);
                    fss = ((DirectoryInfo)info).GetAccessControl();
                }
                else
                {
                    info = new FileInfo(alternativeFilepath);
                    fss = ((FileInfo)info).GetAccessControl();
                }
                InsertFileDescriptorRelation(fileName, fss, false, null);
                // try to find illegitimate soons
                if (info as DirectoryInfo != null)
                {
                    // analyse SD of files in directory
                    AnalyzeFile(fileName, (DirectoryInfo)info, fss.GetOwner(typeof(SecurityIdentifier)).Value);
                    // find hidden relations
                    AnalyzeGPODirectory(fileName, (DirectoryInfo)info);
                }
            }
            catch (Exception ex)
            {
                Trace.WriteLine("An exception occured while working on the file '" + fileName + "':" + ex.Message);
            }
        }

        private void AnalyzeGPODirectory(string filenode, DirectoryInfo directoryInfo)
        {
            AnalyzeLoginLogoffScripts(filenode, directoryInfo);
            AnalyseGPTINI(filenode, directoryInfo);
        }

        private void AnalyzeLoginLogoffScripts(string filenode, DirectoryInfo directoryInfo)
        {
            foreach (string gpoType in new[] { "User", "Machine" })
            {
                foreach (string filename in new[] { "scripts.ini", "psscripts.ini" })
                {
                    string path = directoryInfo.FullName + "\\" + gpoType + "\\Scripts\\" + filename;
                    if (File.Exists(path))
                    {
                        AnalyzeLoginLogoffScript(filenode, directoryInfo, path);
                    }
                }
            }
        }

        private void AnalyzeLoginLogoffScript(string filenode, DirectoryInfo directoryInfo, string path)
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
                AnalyzeScript(filenode, logonscript[i + "cmdline"], RelationType.LogonScript);
                
            }
            for (int i = 0; ; i++)
            {
                if (!logoffscript.ContainsKey(i + "cmdline"))
                {
                    break;
                }
                AnalyzeScript(filenode, logoffscript[i + "cmdline"], RelationType.LogoffScript);
            }
        }

        private void AnalyzeScript(string filenode, string script, RelationType relationType)
        {
            string path = script.Replace(filenode + "\\", "");
            if (!script.Contains("\\"))
                return;
            if (!script.StartsWith("\\\\"))
                return;
            FileInfo fileinfo = new FileInfo(script);
            FileSecurity fss = fileinfo.GetAccessControl();
            InsertFileNode(script);
            Storage.InsertRelation(script, MappingType.Name, filenode, MappingType.Name, relationType);
            InsertFileDescriptorRelation(script, fss, false, null);
        }

        private void AnalyseGPTINI(string filenode, DirectoryInfo directoryInfo)
        {
            RelationType[] privileges = new RelationType[] { 
                RelationType.SeBackupPrivilege, 
                RelationType.SeCreateTokenPrivilege,
                RelationType.SeDebugPrivilege, 
                RelationType.SeEnableDelegationPrivilege, 
                RelationType.SeSyncAgentPrivilege, 
                RelationType.SeTakeOwnershipPrivilege,
                RelationType.SeTcbPrivilege, 
                RelationType.SeTrustedCredManAccessPrivilege,
            };
            string path = directoryInfo.FullName + @"\Machine\Microsoft\Windows nt\SecEdit\GptTmpl.inf";
            if (File.Exists(path))
            {
                using (StreamReader file = new System.IO.StreamReader(path))
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
                                            Storage.InsertRelation(user.Substring(1), MappingType.Sid, filenode, MappingType.Name, privilege);
                                        }
                                        else
                                        {
                                            Storage.InsertRelation(user, MappingType.Name, filenode, MappingType.Name, privilege);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }


        private void AnalyzeFile(string filenode, DirectoryInfo info, string sidOwner)
        {
            foreach( DirectoryInfo directory in info.GetDirectories())
            {
                // is the subdirectory an inheritage ?
                if (InsertFileDescriptorRelation(directory.FullName, directory.GetAccessControl(), true, sidOwner))
                {
                    //no: do not inherit file permission
                    InsertFileNode(directory.FullName);
                    Storage.InsertRelation(directory.FullName, MappingType.Name, filenode, MappingType.Name, RelationType.file_hierarchy);
                    AnalyzeFile(directory.FullName, directory, directory.GetAccessControl().GetOwner(typeof(SecurityIdentifier)).Value);
                }
                else
                {
                    // current directory inherit permission, ignore it
                    AnalyzeFile(filenode, directory, sidOwner);
                }
            }
            foreach (FileInfo file in info.GetFiles())
            {
                if (InsertFileDescriptorRelation(file.FullName, file.GetAccessControl(), true, sidOwner))
                {
                    InsertFileNode(file.FullName);
                    Storage.InsertRelation(file.FullName, MappingType.Name, filenode, MappingType.Name, RelationType.file_hierarchy);
                }
            }
        }


        // return true if there is new relation(s) created
        private bool InsertFileDescriptorRelation(string filenode, FileSystemSecurity sd, bool skipInherited, string knownOwner)
        {
            bool newRelation = false;
            if (!sd.GetOwner(typeof(SecurityIdentifier)).Value.Equals(knownOwner, StringComparison.InvariantCultureIgnoreCase))
            {
                Storage.InsertRelation(sd.GetOwner(typeof(SecurityIdentifier)).Value, MappingType.Sid, filenode, MappingType.Name, RelationType.FILE_OWNER);
                newRelation = true;
            }
            // relations can be duplicated - will slow down import 
            Dictionary<string, List<RelationType>> relationToAdd = new Dictionary<string, List<RelationType>>();
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
            foreach (string target in relationToAdd.Keys)
            {
                foreach (RelationType link in relationToAdd[target])
                {
                    Storage.InsertRelation(target, MappingType.Sid, filenode, MappingType.Name, link);
                    newRelation = true;
                }
            }
            return newRelation;
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
