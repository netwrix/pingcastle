//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Permissions;

namespace PingCastle.ADWS
{
    public class DomainLocator
    {
        [Flags]
        public enum DSGETDCNAME_FLAGS : uint
        {
            DS_FORCE_REDISCOVERY = 0x00000001,
            DS_DIRECTORY_SERVICE_REQUIRED = 0x00000010,
            DS_DIRECTORY_SERVICE_PREFERRED = 0x00000020,
            DS_GC_SERVER_REQUIRED = 0x00000040,
            DS_PDC_REQUIRED = 0x00000080,
            DS_BACKGROUND_ONLY = 0x00000100,
            DS_IP_REQUIRED = 0x00000200,
            DS_KDC_REQUIRED = 0x00000400,
            DS_TIMESERV_REQUIRED = 0x00000800,
            DS_WRITABLE_REQUIRED = 0x00001000,
            DS_GOOD_TIMESERV_PREFERRED = 0x00002000,
            DS_AVOID_SELF = 0x00004000,
            DS_ONLY_LDAP_NEEDED = 0x00008000,
            DS_IS_FLAT_NAME = 0x00010000,
            DS_IS_DNS_NAME = 0x00020000,
            DS_RETURN_DNS_NAME = 0x40000000,
            DS_RETURN_FLAT_NAME = 0x80000000,
            DS_WEB_SERVICE_REQUIRED = 0x00100000,
        }

        [DllImport("libPingCastlesmb", EntryPoint = "DsGetDcName", CharSet = CharSet.Ansi)]
        private static extern int DsGetDcNameUnix
        (
            string ComputerName,
            string DomainName,
            [In] IntPtr DomainGuid,
            string SiteName,
            DSGETDCNAME_FLAGS Flags,
            out IntPtr pDOMAIN_CONTROLLER_INFO
        );

        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int DsGetDcName
        (
            [MarshalAs(UnmanagedType.LPWStr)]
            string ComputerName,
            [MarshalAs(UnmanagedType.LPWStr)]
            string DomainName,
            [In] IntPtr DomainGuid,
            [MarshalAs(UnmanagedType.LPWStr)]
            string SiteName,
            DSGETDCNAME_FLAGS Flags,
            out IntPtr pDOMAIN_CONTROLLER_INFO
        );

        [DllImport("Netapi32", CharSet = CharSet.Auto)]
        internal static extern int NetApiBufferFree(IntPtr Buffer);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct DOMAIN_CONTROLLER_INFO
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string DomainControllerName;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string DomainControllerAddress;
            public uint DomainControllerAddressType;
            public Guid DomainGuid;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string DomainName;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string DnsForestName;
            public uint Flags;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string DcSiteName;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string ClientSiteName;
        }

        string Server;
        PlatformID platform;

        public DomainLocator(string server)
        {
            Server = server;
            platform = Environment.OSVersion.Platform;
        }

        public bool LocateDomainFromNetbios(string netbios, out string domain, out string forest)
        {
            return LocateSomething(netbios, out domain, out forest, DSGETDCNAME_FLAGS.DS_IS_FLAT_NAME |
                                                                    DSGETDCNAME_FLAGS.DS_RETURN_DNS_NAME |
                                                                    DSGETDCNAME_FLAGS.DS_ONLY_LDAP_NEEDED);
        }

        public bool LocateNetbiosFromFQDN(string fqdn, out string netbios, out string forest)
        {
            return LocateSomething(fqdn, out netbios, out forest, DSGETDCNAME_FLAGS.DS_IS_DNS_NAME |
                                                                    DSGETDCNAME_FLAGS.DS_RETURN_FLAT_NAME |
                                                                    DSGETDCNAME_FLAGS.DS_ONLY_LDAP_NEEDED);
        }

        [SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        internal static string GetDC(string domain, bool ADWS, bool forceRediscovery)
        {
            DOMAIN_CONTROLLER_INFO domainInfo;
            const int ERROR_SUCCESS = 0;
            IntPtr pDCI = IntPtr.Zero;
            try
            {
                var flags = DSGETDCNAME_FLAGS.DS_DIRECTORY_SERVICE_REQUIRED |
                            DSGETDCNAME_FLAGS.DS_RETURN_DNS_NAME |
                            DSGETDCNAME_FLAGS.DS_IP_REQUIRED;
                if (ADWS)
                {
                    flags |= DSGETDCNAME_FLAGS.DS_WEB_SERVICE_REQUIRED;
                }
                if (forceRediscovery)
                {
                    flags |= DSGETDCNAME_FLAGS.DS_FORCE_REDISCOVERY;
                }
                int val = DsGetDcName("", domain, IntPtr.Zero, "", flags, out pDCI);
                //check return value for error
                if (ERROR_SUCCESS == val)
                {
                    domainInfo = (DOMAIN_CONTROLLER_INFO)Marshal.PtrToStructure(pDCI, typeof(DOMAIN_CONTROLLER_INFO));

                    return domainInfo.DomainControllerName.Substring(2);
                }
                else
                {
                    throw new Win32Exception(val);
                }
            }
            finally
            {
                if (pDCI != IntPtr.Zero)
                    NetApiBufferFree(pDCI);
            }
        }

        [SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        bool LocateSomething(string intput, out string domain, out string forest, DSGETDCNAME_FLAGS flag)
        {
            IntPtr DomainInfoResolution;
            domain = null;
            forest = null;
            Trace.WriteLine("Trying to solve " + intput + "(" + DateTime.Now.ToString("u") + ")");

            int ret;
            if (platform != PlatformID.Win32NT)
            {
                ret = DsGetDcNameUnix(Server, intput, IntPtr.Zero, null, flag, out DomainInfoResolution);
            }
            else
            {
                ret = DsGetDcName(Server, intput, IntPtr.Zero, null, flag, out DomainInfoResolution);
            }
            if (ret == 0)
            {
                Trace.WriteLine("DsGetDcName for " + intput + " succeeded (" + DateTime.Now.ToString("u") + ")");
                DOMAIN_CONTROLLER_INFO di = (DOMAIN_CONTROLLER_INFO)Marshal.PtrToStructure(DomainInfoResolution, typeof(DOMAIN_CONTROLLER_INFO));
                domain = di.DomainName.ToLowerInvariant();
                forest = di.DnsForestName.ToLowerInvariant();
                NetApiBufferFree(DomainInfoResolution);
                return true;
            }
            else if (ret == 0x0000054B)
            {
                Trace.WriteLine("DsGetDcName for " + intput + " domain not found (" + DateTime.Now.ToString("u") + ")");
            }
            else
            {
                Trace.WriteLine("DsGetDcName for " + intput + " failed 0x" + ret.ToString("x") + " (" + DateTime.Now.ToString("u") + ")");
            }
            return false;
        }
    }
}
