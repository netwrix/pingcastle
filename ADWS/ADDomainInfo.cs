//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices;
using System.Security.Permissions;
using System.Security.Principal;
using System.Xml;

namespace PingCastle.ADWS
{
    public class ADDomainInfo
    {

        public string ConfigurationNamingContext { get; set; }
        public DateTime CreationDate { get; set; }
        public string DefaultNamingContext { get; set; }
        public string DnsHostName { get; set; }
        public int DomainFunctionality { get; set; }
        private string _domainName = null;
        public string DomainName
        {
            get
            {
                if (_domainName == null)
                {
                    _domainName = DefaultNamingContext.Replace(",DC=", ".").Replace("DC=", "").ToLowerInvariant();
                }
                return _domainName;
            }
        }
        private string _forestName = null;
        public string ForestName
        {
            get
            {
                if (_forestName == null)
                {
                    _forestName = ConfigurationNamingContext.Replace("CN=Configuration,", "").Replace(",DC=", ".").Replace("DC=", "").ToLowerInvariant();
                }
                return _forestName;
            }
        }
        public SecurityIdentifier DomainSid { get; set; }
        public int ForestFunctionality { get; set; }
        public string NetBIOSName { get; set; }
        public string RootDomainNamingContext { get; set; }
        public string SchemaNamingContext { get; set; }
        public int SchemaVersion { get; set; }
        public int SchemaInternalVersion { get; set; }
        public DateTime SchemaLastChanged { get; set; }
        public List<string> NamingContexts { get; set; }

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

        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        public static ADDomainInfo Create(DirectoryEntry rootDSE)
        {
            ADDomainInfo info = new ADDomainInfo();
            info.DefaultNamingContext = rootDSE.Properties["defaultNamingContext"].Value as string;
            info.ConfigurationNamingContext = rootDSE.Properties["configurationNamingContext"].Value as string;
            info.DnsHostName = rootDSE.Properties["dnsHostName"].Value as string;
            if (rootDSE.Properties.Contains("domainFunctionality"))
                info.DomainFunctionality = int.Parse(rootDSE.Properties["domainFunctionality"].Value as string);
            if (rootDSE.Properties.Contains("forestFunctionality"))
                info.ForestFunctionality = int.Parse(rootDSE.Properties["forestFunctionality"].Value as string);
            if (rootDSE.Properties.Contains("netBIOSName"))
                info.NetBIOSName = rootDSE.Properties["netBIOSName"].Value as string;
            info.RootDomainNamingContext = rootDSE.Properties["rootDomainNamingContext"].Value as string;
            info.SchemaNamingContext = rootDSE.Properties["schemaNamingContext"].Value as string;
            Trace.WriteLine("supportedLDAPVersion: ");
            object[] supportedLDAPVersion = rootDSE.Properties["supportedLDAPVersion"].Value as object[];
            if (supportedLDAPVersion != null)
                foreach (string version in supportedLDAPVersion)
                {
                    Trace.WriteLine(version);
                }
            Trace.WriteLine("supportedControl: ");
            object[] supportedControl = rootDSE.Properties["supportedControl"].Value as object[];
            if (supportedControl != null)
                foreach (string control in supportedControl)
                {
                    Trace.WriteLine(control);
                }
            Trace.WriteLine("supportedLDAPVersion: ");
            info.NamingContexts = new List<string>();
            foreach (var nc in (object[])rootDSE.Properties["namingContexts"].Value)
            {
                info.NamingContexts.Add((string)nc);
            }
            return info;
        }

        public static ADDomainInfo Create(top data)
        {
            ADDomainInfo info = new ADDomainInfo();
            foreach (XmlElement item in data.Any)
            {
                string attribute = StripNamespace(item.Name);

                switch (attribute)
                {
                    case "configurationNamingContext":
                        info.ConfigurationNamingContext = ExtractStringValue(item);
                        break;
                    case "defaultNamingContext":
                        info.DefaultNamingContext = ExtractStringValue(item);
                        break;
                    case "dnsHostName":
                        info.DnsHostName = ExtractStringValue(item);
                        break;
                    case "domainFunctionality":
                        info.DomainFunctionality = ExtractIntValue(item);
                        break;
                    case "forestFunctionality":
                        info.ForestFunctionality = ExtractIntValue(item);
                        break;
                    case "netBIOSName":
                        info.NetBIOSName = ExtractStringValue(item);
                        break;
                    case "namingContexts":
                        info.NamingContexts = new List<string>(ExtractStringArrayValue(item));
                        break;
                    case "rootDomainNamingContext":
                        info.RootDomainNamingContext = ExtractStringValue(item);
                        break;
                    case "schemaNamingContext":
                        info.SchemaNamingContext = ExtractStringValue(item);
                        break;
                    case "supportedLDAPVersion":
                        Trace.WriteLine("supportedLDAPVersion: ");
                        if (item.ChildNodes != null)
                        {
                            foreach (XmlNode child in item.ChildNodes)
                                if (child != null)
                                {
                                    Trace.WriteLine(child.InnerText);
                                }
                        }
                        break;
                    case "supportedControl":
                        Trace.WriteLine("supportedControl: ");
                        if (item.ChildNodes != null)
                        {
                            foreach (XmlNode child in item.ChildNodes)
                                if (child != null)
                                {
                                    Trace.WriteLine(child.InnerText);
                                }
                        }
                        break;
                    default:
                        Trace.WriteLine("Other attribute found:" + attribute);
                        break;

                }
            }
            return info;
        }
    }
}
