//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Healthcheck;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices;
using System.Globalization;
using System.Security.AccessControl;
using System.Security.Cryptography.X509Certificates;
using System.Security.Permissions;
using System.Security.Principal;
using System.Text;
using System.Xml;

namespace PingCastle.ADWS
{
	[DebuggerDisplay("{DistinguishedName}")]
    public class ADItem
    {
        public class ReplPropertyMetaDataItem
        {
            public int AttrType { get; set; }
            public int Version { get; set; }
            public DateTime LastOriginatingChange { get; set; }
            public Guid LastOriginatingDsaInvocationID { get; set; }
            public long UsnOriginatingChange { get; set; }
			public long UsnLocalChange { get; set; }
        }


        public int AdminCount { get; set; }
		public string AttributeID { get; set; }
        public X509Certificate2Collection CACertificate { get; set; }
        public string Class { get; set; }
        public string Description { get; set; }
        public string DistinguishedName { get; set; }
        public string DisplayName { get; set; }
        public string DnsRoot { get; set; }
        public string DNSHostName { get; set; }
        public string DSHeuristics { get; set; }
        public int DSMachineAccountQuota { get; set; }
        public int Flags { get; set; }
        public string GPLink { get; set; }
        public string GPCFileSysPath { get; set; }
        public DateTime LastLogonTimestamp { get; set; }
		public string lDAPDisplayName { get; set; }
        public string Location { get; set; }
        public string[] Member { get; set; }
        public string[] MemberOf { get; set; }
        public int msDSSupportedEncryptionTypes { get; set; }
		public long msDSMinimumPasswordAge { get; set; }
		public long msDSMaximumPasswordAge { get; set; }
		public int msDSMinimumPasswordLength { get; set; }
		public bool msDSPasswordComplexityEnabled { get; set; }
		public int msDSPasswordHistoryLength { get; set; }
		public int msDSLockoutThreshold { get; set; }
		public long msDSLockoutObservationWindow { get; set; }
		public long msDSLockoutDuration { get; set; }
		public bool msDSPasswordReversibleEncryptionEnabled { get; set; }
        public List<HealthCheckTrustDomainInfoData> msDSTrustForestTrustInfo { get; set; }
        public string Name { get; set; }
        public string NetBIOSName { get; set; }
        public ActiveDirectorySecurity NTSecurityDescriptor { get; set; }
        public SecurityIdentifier ObjectSid { get; set; }
		public int ObjectVersion { get; set; }
        public string OperatingSystem { get; set; }
        public int PrimaryGroupID { get; set; }
        public DateTime PwdLastSet { get; set; }
        public string SAMAccountName { get; set; }
		public byte[] SchemaInfo { get; set; }
        public string ScriptPath { get; set; }
        public SecurityIdentifier SecurityIdentifier { get; set; }
		public string[] ServicePrincipalName { get; set; }
        public SecurityIdentifier[] SIDHistory { get; set; }
        public string[] SiteObjectBL { get; set; }
        public int TrustAttributes { get; set; }
        public int TrustDirection { get; set; }
        public string TrustPartner { get; set; }
        public int TrustType { get; set; }
        public int UserAccountControl { get; set; }
        public DateTime WhenCreated { get; set; }
        public DateTime WhenChanged { get; set; }
        public Dictionary<int, ReplPropertyMetaDataItem> ReplPropertyMetaData { get; set; }

        private static string StripNamespace(string input)
        {
            int index = input.IndexOf(':');
            if (index >= 0)
            {
                return input.Substring(index + 1);
            }
            return input;
        }

        private static string ExtractStringValue(XmlNode item)
        {
            XmlNode child = item.FirstChild;
            if (child != null && item.FirstChild != null)
            {
                return child.InnerText;
            }
            return String.Empty;
        }

        private static int ExtractIntValue(XmlNode item)
        {
            XmlNode child = item.FirstChild;
            if (child != null && item.FirstChild != null)
            {
                return int.Parse(child.InnerText);
            }
            return 0;
        }

		private static long ExtractLongValue(XmlNode item)
		{
			XmlNode child = item.FirstChild;
			if (child != null && item.FirstChild != null)
			{
				return long.Parse(child.InnerText);
			}
			return 0;
		}

		private static bool ExtractBoolValue(XmlNode item)
		{
			XmlNode child = item.FirstChild;
			if (child != null && item.FirstChild != null)
			{
				return bool.Parse(child.InnerText);
			}
			return false;
		}

        private static DateTime ExtractDateValue(XmlNode item)
        {
            XmlNode child = item.FirstChild;
            if (child != null && item.FirstChild != null)
            {
				return SafeExtractDateTimeFromLong(long.Parse(child.InnerText));
            }
            return DateTime.MinValue;
        }

        private static ActiveDirectorySecurity ExtractSDValue(XmlNode child)
        {
            string value = ExtractStringValue(child);
            byte[] data = Convert.FromBase64String(value);
            ActiveDirectorySecurity sd = new ActiveDirectorySecurity();
            sd.SetSecurityDescriptorBinaryForm(data);
            return sd;
        }

        private static SecurityIdentifier ExtractSIDValue(XmlNode child)
        {
            string value = ExtractStringValue(child);
            byte[] data = Convert.FromBase64String(value);
            return new SecurityIdentifier(data, 0);
        }

        // see https://msdn.microsoft.com/en-us/library/cc223786.aspx
        private static List<HealthCheckTrustDomainInfoData> ConvertByteToTrustInfo(byte[] data)
        {
            List<HealthCheckTrustDomainInfoData> output = new List<HealthCheckTrustDomainInfoData>();
            Trace.WriteLine("Beginning to analyze a forestinfo data " + Convert.ToBase64String(data));
            int version = BitConverter.ToInt32(data, 0);
            if (version != 1)
            {
                Trace.WriteLine("trust info version incompatible : " + version);
                return output;
            }
            int recordcount = BitConverter.ToInt32(data, 4);
            Trace.WriteLine("Number of records to analyze: " + recordcount);
            int pointer = 8;
            for (int i = 0; i < recordcount; i++)
            {
                int recordSize = 17;
                int recordLen = BitConverter.ToInt32(data, pointer);
                byte recordType = data[pointer + 16];
				DateTime dt = SafeExtractDateTimeFromLong((((long)BitConverter.ToInt32(data, pointer + 8)) << 32) + BitConverter.ToInt32(data, pointer + 12));
                if (recordType == 0 || recordType == 1)
                {
                    int nameLen = BitConverter.ToInt32(data, pointer + recordSize);
                    string name = UnicodeEncoding.UTF8.GetString(data, pointer + recordSize + 4, nameLen);
                    Trace.WriteLine("RecordType 0 or 1: name=" + name);
                }
                else if (recordType == 2)
                {
                    Trace.WriteLine("RecordType 2");
                    int tempPointer = pointer + recordSize;
                    int sidLen = BitConverter.ToInt32(data, tempPointer);
                    tempPointer += 4;
                    SecurityIdentifier sid = new SecurityIdentifier(data, tempPointer);
                    tempPointer += sidLen;
                    int DnsNameLen = BitConverter.ToInt32(data, tempPointer);
                    tempPointer += 4;
                    string DnsName = UnicodeEncoding.UTF8.GetString(data, tempPointer, DnsNameLen);
                    tempPointer += DnsNameLen;
                    int NetbiosNameLen = BitConverter.ToInt32(data, tempPointer);
                    tempPointer += 4;
                    string NetbiosName = UnicodeEncoding.UTF8.GetString(data, tempPointer, NetbiosNameLen);
                    tempPointer += NetbiosNameLen;

                    HealthCheckTrustDomainInfoData domaininfoc = new HealthCheckTrustDomainInfoData();
                    domaininfoc.CreationDate = dt;
                    domaininfoc.DnsName = DnsName.ToLowerInvariant();
                    domaininfoc.NetbiosName = NetbiosName;
                    domaininfoc.Sid = sid.Value;
                    output.Add(domaininfoc);
                }
                pointer += 4 + recordLen;
            }
            return output;
        }

        private static Dictionary<int, ReplPropertyMetaDataItem> ConvertByteToMetaDataInfo(byte[] data)
        {
            var output = new Dictionary<int, ReplPropertyMetaDataItem>();
            //Trace.WriteLine("Beginning to analyze a replpropertymetadata data " + Convert.ToBase64String(data));
            int version = BitConverter.ToInt32(data, 0);
            if (version != 1)
            {
                Trace.WriteLine("trust info version incompatible : " + version);
                return output;
            }
            int recordcount = BitConverter.ToInt32(data, 8);
            //Trace.WriteLine("Number of records to analyze: " + recordcount);
            int pointer = 16;
            for (int i = 0; i < recordcount; i++)
            {
                var item = new ReplPropertyMetaDataItem();
                item.AttrType = BitConverter.ToInt32(data, pointer);
                item.Version = BitConverter.ToInt32(data, pointer + 4);
				long filetime = BitConverter.ToInt64(data, pointer + 8) * 10000000;
                item.LastOriginatingChange = DateTime.FromFileTime(filetime);
				byte[] guid = new byte[16];
				Array.Copy(data, pointer + 16, guid, 0, 16);
				item.LastOriginatingDsaInvocationID = new Guid(guid);
                item.UsnOriginatingChange = BitConverter.ToInt64(data, pointer + 32);
                item.UsnLocalChange = BitConverter.ToInt64(data, pointer + 40);
                pointer += 48;
                output[item.AttrType] = item;
            }
            return output;
        }

        private static List<HealthCheckTrustDomainInfoData> ExtractTrustForestInfo(XmlNode child)
        {
            string value = ExtractStringValue(child);
            return ConvertByteToTrustInfo(Convert.FromBase64String(value));
        }

        private static Dictionary<int, ReplPropertyMetaDataItem> ExtractReplPropertyMetadata(XmlNode child)
        {
            string value = ExtractStringValue(child);
            return ConvertByteToMetaDataInfo(Convert.FromBase64String(value));
        }

        private static string[] ExtractStringArrayValue(XmlNode item)
        {
            XmlNode child = item.FirstChild;
            List<string> list = new List<string>();
            while (child != null)
            {
                list.Add(child.InnerText);
                child = child.NextSibling;
            }
            return list.ToArray();
        }


        private static X509Certificate2Collection ExtractCertificateStore(XmlNode item)
        {
            XmlNode child = item.FirstChild;
            X509Certificate2Collection store = new X509Certificate2Collection();
            while (child != null)
            {
                store.Add(new X509Certificate2(Convert.FromBase64String(child.InnerText)));
                child = child.NextSibling;
            }
            return store;
        }

        private static SecurityIdentifier[] ExtractSIDArrayValue(XmlNode item)
        {
            XmlNode child = item.FirstChild;
            List<SecurityIdentifier> list = new List<SecurityIdentifier>();
            while (child != null)
            {
                byte[] data = Convert.FromBase64String(child.InnerText);
                list.Add(new SecurityIdentifier(data, 0));
                child = child.NextSibling;
            }
            return list.ToArray();
        }

        public static ADItem Create(XmlElement item)
        {
            ADItem aditem = new ADItem();
            aditem.Class = StripNamespace(item.Name).ToLowerInvariant();
            XmlNode child = item.FirstChild;

            while (child != null && child is XmlElement)
            {
                string name = StripNamespace(child.Name);
                switch(name)
                {
                    case "adminCount":
                        aditem.AdminCount = ExtractIntValue(child);
                        break;
					case "attributeID":
						aditem.AttributeID = ExtractStringValue(child);
						break;
                    case "cACertificate":
                        aditem.CACertificate = ExtractCertificateStore(child);
                        break;
                    case "description":
                        aditem.Description = ExtractStringValue(child);
                        break;
                    case "displayName":
                        aditem.DisplayName = ExtractStringValue(child);
                        break;
                    case "distinguishedName":
                        aditem.DistinguishedName = ExtractStringValue(child);
                        break;
                    case "dNSHostName":
                        aditem.DNSHostName = ExtractStringValue(child);
                        break;
                    case "dnsRoot":
                        aditem.DnsRoot = ExtractStringValue(child).ToLowerInvariant();
                        break;
                    case "dSHeuristics":
                        aditem.DSHeuristics = ExtractStringValue(child);
                        break;
                    case "flags":
                        aditem.Flags = ExtractIntValue(child);
                        break;
                    case "gPCFileSysPath":
                        aditem.GPCFileSysPath = ExtractStringValue(child);
                        break;
                    case "gPLink":
                        aditem.GPLink = ExtractStringValue(child);
                        break;
                    case "lastLogonTimestamp":
                        aditem.LastLogonTimestamp = ExtractDateValue(child);
                        break;
					case "lDAPDisplayName":
						aditem.lDAPDisplayName = ExtractStringValue(child);
						break;
                    case "location":
                        aditem.Location = ExtractStringValue(child);
                        break;
                    case "memberOf":
                        aditem.MemberOf = ExtractStringArrayValue(child);
                        break;
                    case "member":
                        aditem.Member = ExtractStringArrayValue(child);
                        break;
                    case "name":
                        aditem.Name = ExtractStringValue(child);
                        break;
                    case "ms-DS-MachineAccountQuota":
                        aditem.DSMachineAccountQuota = ExtractIntValue(child);
                        break;
                    case "msDS-SupportedEncryptionTypes":
                        aditem.msDSSupportedEncryptionTypes = ExtractIntValue(child);
                        break;
                    case "msDS-TrustForestTrustInfo":
                        aditem.msDSTrustForestTrustInfo = ExtractTrustForestInfo(child);
                        break;
					case "msDS-MinimumPasswordAge":
						aditem.msDSMinimumPasswordAge = ExtractLongValue(child);
						break;
					case "msDS-MaximumPasswordAge":
						aditem.msDSMaximumPasswordAge = ExtractLongValue(child);
						break;
					case "msDS-MinimumPasswordLength":
						aditem.msDSMinimumPasswordLength = ExtractIntValue(child);
						break;
					case "msDS-PasswordComplexityEnabled":
						aditem.msDSPasswordComplexityEnabled = ExtractBoolValue(child);
						break;
					case "msDS-PasswordHistoryLength":
						aditem.msDSPasswordHistoryLength = ExtractIntValue(child);
						break;
					case "msDS-LockoutThreshold":
						aditem.msDSLockoutThreshold = ExtractIntValue(child);
						break;
					case "msDS-LockoutObservationWindow":
						aditem.msDSLockoutObservationWindow = ExtractLongValue(child);
						break;
					case "msDS-LockoutDuration":
						aditem.msDSLockoutDuration = ExtractLongValue(child);
						break;
					case "msDS-PasswordReversibleEncryptionEnabled":
						aditem.msDSPasswordReversibleEncryptionEnabled = ExtractBoolValue(child);
						break;
                    case "nETBIOSName":
                        aditem.NetBIOSName = ExtractStringValue(child);
                        break;
                    case "nTSecurityDescriptor":
                        aditem.NTSecurityDescriptor = ExtractSDValue(child);
                        break;
                    case "objectSid":
                        aditem.ObjectSid = ExtractSIDValue(child);
                        break;
					case "objectVersion":
						aditem.ObjectVersion = ExtractIntValue(child);
						break;
                    case "operatingSystem":
                        aditem.OperatingSystem = ExtractStringValue(child);
                        break;
                    case "primaryGroupID":
                        aditem.PrimaryGroupID = ExtractIntValue(child);
                        break;
                    case "pwdLastSet":
                        aditem.PwdLastSet = ExtractDateValue(child);
                        break;
                    case "replPropertyMetaData":
                        aditem.ReplPropertyMetaData = ExtractReplPropertyMetadata(child);
                        break;
                    case "sAMAccountName":
                        aditem.SAMAccountName = ExtractStringValue(child);
                        break;
					case "schemaInfo":
						aditem.SchemaInfo = Convert.FromBase64String(ExtractStringValue(child));
						break;
                    case "scriptPath":
                        aditem.ScriptPath = ExtractStringValue(child);
                        break;
                    case "securityIdentifier":
                        aditem.SecurityIdentifier = ExtractSIDValue(child);
                        break;
					case "servicePrincipalName":
						aditem.ServicePrincipalName = ExtractStringArrayValue(child);
						break;
                    case "sIDHistory":
                        aditem.SIDHistory = ExtractSIDArrayValue(child);
                        break;
                    case "siteObjectBL":
                        aditem.SiteObjectBL = ExtractStringArrayValue(child);
                        break;
                    case "trustAttributes":
                        aditem.TrustAttributes = ExtractIntValue(child);
                        break;
                    case "trustDirection":
                        aditem.TrustDirection = ExtractIntValue(child);
                        break;
                    case "trustPartner":
                        aditem.TrustPartner = ExtractStringValue(child).ToLowerInvariant();
                        break;
                    case "trustType":
                        aditem.TrustType = ExtractIntValue(child);
                        break;
                    case "userAccountControl":
                        aditem.UserAccountControl = ExtractIntValue(child);
                        break;
                    case "whenCreated":
                        aditem.WhenCreated = DateTime.ParseExact(ExtractStringValue(child), "yyyyMMddHHmmss.f'Z'", CultureInfo.InvariantCulture);
                        break;
                    case "whenChanged":
                        aditem.WhenChanged = DateTime.ParseExact(ExtractStringValue(child), "yyyyMMddHHmmss.f'Z'", CultureInfo.InvariantCulture);
                        break;
                }
                child = child.NextSibling;
            }          
            return aditem;
        }

		// the AD is supposed to store Filetime as long.
		// Samba can return an out of range value
		private static DateTime SafeExtractDateTimeFromLong(long value)
		{
			try
			{
				return DateTime.FromFileTime(value);
			}
			catch
			{
				return DateTime.MinValue;
			}
		}

        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        public static ADItem Create(SearchResult sr, bool nTSecurityDescriptor)
        {
            ADItem aditem = new ADItem();
            // note: nTSecurityDescriptor is not present in the property except when run under admin (because allowed to read it)
            // this workaround is here when running under lower permission
            if (nTSecurityDescriptor)
            {
                aditem.NTSecurityDescriptor = sr.GetDirectoryEntry().ObjectSecurity;
            }
            foreach (string name in sr.Properties.PropertyNames)
            {
                switch (name)
                {
                    case "admincount":
                        aditem.AdminCount = (int) sr.Properties[name][0];
                        break;
					case "attributeid":
						aditem.AttributeID = sr.Properties[name][0] as string;
                        break;
                    case "adspath":
                        break;
                    case "cacertificate":
                        X509Certificate2Collection store = new X509Certificate2Collection();
                        foreach( byte[] data in sr.Properties["cACertificate"])
                        {
                            store.Add(new X509Certificate2(data));
                        }
                        aditem.CACertificate = store;
                        break;
                    case "description":
                        aditem.Description = sr.Properties[name][0] as string;
                        break;
                    case "displayname":
                        aditem.DisplayName = sr.Properties[name][0] as string;
                        break;
                    case "distinguishedname":
                        aditem.DistinguishedName = sr.Properties[name][0] as string;
                        break;
                    case "dnshostname":
                        aditem.DNSHostName = sr.Properties[name][0] as string;
                        break;
                    case "dnsroot":
                        aditem.DnsRoot = (sr.Properties[name][0] as string).ToLowerInvariant();
                        break;
                    case "dsheuristics":
                        aditem.DSHeuristics = sr.Properties[name][0] as string;
                        break;
                    case "flags":
                        aditem.Flags = (int)sr.Properties[name][0];
                        break;
                    case "gpcfilesyspath":
                        aditem.GPCFileSysPath = sr.Properties[name][0] as string;
                        break;
                    case "gplink":
                        aditem.GPLink = sr.Properties[name][0] as string;
                        break;
                    case "lastlogontimestamp":
						aditem.LastLogonTimestamp = SafeExtractDateTimeFromLong((long)sr.Properties[name][0]);
                        break;
					case "ldapdisplayname":
						aditem.lDAPDisplayName = sr.Properties[name][0] as string;
						break;
                    case "location":
                        aditem.Location = sr.Properties[name][0] as string;
                        break;
                    case "memberof":
                        {
                            List<string> list = new List<string>();
                            foreach (string data in sr.Properties[name])
                            {
                                list.Add(data);
                            }
                            aditem.MemberOf = list.ToArray();
                        }
                        break;
                    case "member":
                        {
                            List<string> list = new List<string>();
                            foreach (string data in sr.Properties[name])
                            {
                                list.Add(data);
                            }
                            aditem.Member = list.ToArray();
                        }
                        break;
                    case "name":
                        aditem.Name = sr.Properties[name][0] as string;
                        break;
                    case "ms-ds-machineaccountquota":
                        aditem.DSMachineAccountQuota = (int)sr.Properties[name][0];
                        break;
                    case "msds-supportedencryptiontypes":
                        aditem.msDSSupportedEncryptionTypes = (int)sr.Properties[name][0];
                        break;
                    case "msds-trustforesttrustinfo":
                        aditem.msDSTrustForestTrustInfo = ConvertByteToTrustInfo((byte[])sr.Properties[name][0]);
                        break;
					case "msds-minimumpasswordage":
						aditem.msDSMinimumPasswordAge = (long)sr.Properties[name][0];
						break;
					case "msds-maximumpasswordage":
						aditem.msDSMaximumPasswordAge = (long)sr.Properties[name][0];
						break;
					case "msds-minimumpasswordlength":
						aditem.msDSMinimumPasswordLength = (int)sr.Properties[name][0];
						break;
					case "msds-passwordcomplexityenabled":
						aditem.msDSPasswordComplexityEnabled = (bool)sr.Properties[name][0];
						break;
					case "msds-passwordhistorylength":
						aditem.msDSPasswordHistoryLength = (int)sr.Properties[name][0];
						break;
					case "msds-lockoutthreshold":
						aditem.msDSLockoutThreshold = (int)sr.Properties[name][0];
						break;
					case "msds-lockoutobservationwindow":
						aditem.msDSLockoutObservationWindow = (long)sr.Properties[name][0];
						break;
					case "msds-lockoutduration":
						aditem.msDSLockoutDuration = (long)sr.Properties[name][0];
						break;
					case "msds-passwordreversibleencryptionenabled":
						aditem.msDSPasswordReversibleEncryptionEnabled = (bool)sr.Properties[name][0];
						break;
                    case "netbiosname":
                        aditem.NetBIOSName = sr.Properties[name][0] as string;
                        break;
                    case "ntsecuritydescriptor":
                        // ignored
                        break;
                    case "objectclass":
                        aditem.Class = sr.Properties[name][sr.Properties[name].Count-1] as string;
                        break;
                    case "objectsid":
                        aditem.ObjectSid = new SecurityIdentifier((byte[])sr.Properties[name][0],0);
                        break;
					case "objectversion":
						aditem.ObjectVersion = (int)sr.Properties[name][0];
						break;
                    case "operatingsystem":
                        aditem.OperatingSystem = sr.Properties[name][0] as string;
                        break;
                    case "primarygroupid":
                        aditem.PrimaryGroupID = (int)sr.Properties[name][0];
                        break;
                    case "pwdlastset":
						aditem.PwdLastSet = SafeExtractDateTimeFromLong((long)sr.Properties[name][0]);
                        break;
					case "replpropertymetadata":
                        aditem.ReplPropertyMetaData = ConvertByteToMetaDataInfo((byte[])sr.Properties[name][0]);
                        break;
                    case "samaccountname":
                        aditem.SAMAccountName = sr.Properties[name][0] as string;
                        break;
					case "schemainfo":
						aditem.SchemaInfo = (byte[])sr.Properties[name][0];
						break;
                    case "scriptpath":
                        aditem.ScriptPath = sr.Properties[name][0] as string;
                        break;
                    case "securityidentifier":
                        aditem.SecurityIdentifier = new SecurityIdentifier((byte[])sr.Properties[name][0], 0);
                        break;
					case "serviceprincipalname":
						{
							List<string> list = new List<string>();
							foreach (string data in sr.Properties[name])
							{
								list.Add(data);
							}
							aditem.ServicePrincipalName = list.ToArray();
						}
						break;
                    case "sidhistory":
                        {
                            List<SecurityIdentifier> list = new List<SecurityIdentifier>();
                            foreach (byte[] data in sr.Properties[name])
                            {
                                list.Add(new SecurityIdentifier(data, 0));
                            }
                            aditem.SIDHistory = list.ToArray();
                        }
                        break;
                    case "siteobjectbl":
                        {
                            List<string> list = new List<string>();
                            foreach (string data in sr.Properties[name])
                            {
                                list.Add(data);
                            }
                            aditem.SiteObjectBL = list.ToArray();
                        }
                        break;
                    case "trustattributes":
                        aditem.TrustAttributes = (int)sr.Properties[name][0];
                        break;
                    case "trustdirection":
                        aditem.TrustDirection = (int)sr.Properties[name][0];
                        break;
                    case "trustpartner":
                        aditem.TrustPartner = ((string)sr.Properties[name][0]).ToLowerInvariant();
                        break;
                    case "trusttype":
                        aditem.TrustType = (int)sr.Properties[name][0];
                        break;
                    case "useraccountcontrol":
                        aditem.UserAccountControl = (int)sr.Properties[name][0];
                        break;
                    case "whencreated":
                        aditem.WhenCreated = (DateTime)sr.Properties[name][0];
                        break;
                    case "whenchanged":
                        aditem.WhenChanged = (DateTime)sr.Properties[name][0];
                        break;
                    default:
                        Trace.WriteLine("Unknown attribute: " + name);
                        break;
                }
            }
            return aditem;
        }
	}
}
