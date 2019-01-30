//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Healthcheck;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using System.Security.Principal;
using System.Text;

namespace PingCastle
{
    public class NativeMethods
    {
        #region PInvoke Signatures

        [DllImport("advapi32.dll", SetLastError = true, CharSet=CharSet.Unicode)]
        private static extern bool LogonUser(string
        lpszUsername, string lpszDomain, string lpszPassword,
        int dwLogonType, int dwLogonProvider, ref IntPtr phToken);

        // logon types
        const int LOGON32_LOGON_INTERACTIVE = 2;
        const int LOGON32_LOGON_NETWORK = 3;
        const int LOGON32_LOGON_NEW_CREDENTIALS = 9;

        // logon providers
        const int LOGON32_PROVIDER_DEFAULT = 0;
        const int LOGON32_PROVIDER_WINNT50 = 3;
        const int LOGON32_PROVIDER_WINNT40 = 2;
        const int LOGON32_PROVIDER_WINNT35 = 1;

        public static WindowsIdentity GetWindowsIdentityForUser(NetworkCredential credential, string remoteserver)
        {
            IntPtr token = IntPtr.Zero;
            string domain = credential.Domain;
            if (String.IsNullOrEmpty(domain))
                domain = remoteserver;
            Trace.WriteLine("Preparing to login with login = " + credential.UserName + " domain = " + domain);
            bool isSuccess = LogonUser(credential.UserName, domain, credential.Password, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, ref token);
            if (!isSuccess)
            {
                throw new Win32Exception();
            }
            return new WindowsIdentity(token);
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool LookupAccountSid(
            string lpSystemName,
            [MarshalAs(UnmanagedType.LPArray)] byte[] Sid,
            System.Text.StringBuilder lpName,
            ref uint cchName,
            System.Text.StringBuilder ReferencedDomainName,
            ref uint cchReferencedDomainName,
            out SID_NAME_USE peUse);

        const int NO_ERROR = 0;
        const int ERROR_INSUFFICIENT_BUFFER = 122;

        public enum SID_NAME_USE
        {
            SidTypeUser = 1,
            SidTypeGroup,
            SidTypeDomain,
            SidTypeAlias,
            SidTypeWellKnownGroup,
            SidTypeDeletedAccount,
            SidTypeInvalid,
            SidTypeUnknown,
            SidTypeComputer
        }

		public static string ConvertSIDToName(string sidstring, string server)
		{
			string referencedDomain = null;
			return ConvertSIDToName(sidstring, server, out referencedDomain);
		}

        [EnvironmentPermissionAttribute(SecurityAction.Demand, Unrestricted = true)]
        public static string ConvertSIDToName(string sidstring, string server, out string referencedDomain)
        {
            StringBuilder name = new StringBuilder();
            uint cchName = (uint)name.Capacity;
            StringBuilder referencedDomainName = new StringBuilder();
            uint cchReferencedDomainName = (uint)referencedDomainName.Capacity;
            SID_NAME_USE sidUse;

			SecurityIdentifier securityidentifier = null;
			referencedDomain = null;
			try
			{
				securityidentifier = new SecurityIdentifier(sidstring);
			}
			catch (Exception ex)
			{
				Trace.WriteLine("Got " + ex.Message + " when trying to convert " + sidstring + " as sid");
				Trace.WriteLine(ex.StackTrace);
				return sidstring;
			}

            // try to resolve the account using the server
            byte[] Sid = new byte[securityidentifier.BinaryLength];
            securityidentifier.GetBinaryForm(Sid, 0);

            int err = NO_ERROR;
            if (!LookupAccountSid(server, Sid, name, ref cchName, referencedDomainName, ref cchReferencedDomainName, out sidUse))
            {
                err = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                if (err == ERROR_INSUFFICIENT_BUFFER)
                {
                    name.EnsureCapacity((int)cchName);
                    referencedDomainName.EnsureCapacity((int)cchReferencedDomainName);
                    err = NO_ERROR;
                    if (!LookupAccountSid(server, Sid, name, ref cchName, referencedDomainName, ref cchReferencedDomainName, out sidUse))
                        err = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                }
            }
			if (err == 0)
			{
				referencedDomain = referencedDomainName.ToString();
				if (String.IsNullOrEmpty(referencedDomain))
					return name.ToString();
				else
					return referencedDomainName + "\\" + name;
			}
            Trace.WriteLine(@"Error " + err + " when translating " + sidstring + " on " + server);
            return sidstring;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING : IDisposable
        {
            public ushort Length;
            public ushort MaximumLength;
            private IntPtr buffer;

            [SecurityPermission(SecurityAction.LinkDemand)]
            public void Initialize(string s)
            {
                Length = (ushort)(s.Length * 2);
                MaximumLength = (ushort)(Length + 2);
                buffer = Marshal.StringToHGlobalUni(s);
            }

            [SecurityPermission(SecurityAction.LinkDemand)]
            public void Dispose()
            {
                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;
            }
            [SecurityPermission(SecurityAction.LinkDemand)]
            public override string ToString()
            {
				if (Length == 0)
					return String.Empty;
				return Marshal.PtrToStringUni(buffer, Length / 2);
            }
        }


        [DllImport("samlib.dll"), System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Portability", "CA1901:PInvokeDeclarationsShouldBePortable", MessageId = "3")]
        internal static extern int SamConnect(ref UNICODE_STRING serverName, out IntPtr hServerHandle, int desiredAccess, int trusted);
        [DllImport("samlib.dll")]
        internal static extern int SamOpenDomain(IntPtr SamHandle, int DesiredAccess, byte[] DomainId, out IntPtr DomainHandle);
        [DllImport("samlib.dll")]
        internal static extern int SamOpenAlias(IntPtr DomainHandle, int DesiredAccess, int AliasId, out IntPtr AliasHandle);
        [DllImport("samlib.dll")]
        internal static extern int SamGetMembersInAlias(IntPtr AliasHandle, out IntPtr Members, out int CountReturned);
        [DllImport("samlib.dll")]
        internal static extern int SamFreeMemory(IntPtr memory);
        [DllImport("samlib.dll")]
        internal static extern int SamCloseHandle(IntPtr SamHandle);
        [DllImport("advapi32.dll", SetLastError = false)]
        internal static extern int LsaNtStatusToWinError(int status);


        internal enum SHARE_TYPE : uint
        {
            STYPE_DISK = 0,  // Disk Share
            STYPE_PRINTQ = 1,    // Print Queue
            STYPE_DEVICE = 2,    // Communication Device
            STYPE_IPC = 3,       // IPC (Interprocess communication) Share
            STYPE_HIDDEN_DISK = 0x80000000,  // Admin Disk Shares
            STYPE_HIDDEN_PRINT = 0x80000001,  // Admin Print Shares
            STYPE_HIDDEN_DEVICE = 0x80000002,  // Admin Device Shares
            STYPE_HIDDEN_IPC = 0x80000003,  // Admin IPC Shares
            // Need to add flags for
            // STYPE_TEMPORARY
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct SHARE_INFO_503
        {
            public string shi503_netname;
            [MarshalAs(UnmanagedType.U4)]
            public SHARE_TYPE shi503_type;
            public string shi503_remark;
            [MarshalAs(UnmanagedType.U4)]
            public int shi503_permissions;    // used w/ share level security only
            [MarshalAs(UnmanagedType.U4)]
            public int shi503_max_uses;
            [MarshalAs(UnmanagedType.U4)]
            public int shi503_current_uses;
            public string shi503_path;
            public string shi503_passwd;    // used w/ share level security only
            public string shi503_servername;
            [MarshalAs(UnmanagedType.U4)]
            public int shi503_reserved;
            public IntPtr shi503_security_descriptor;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct SHARE_INFO_1
        {
            public string shi1_netname;
            public uint shi1_type;
            public string shi1_remark;
            public SHARE_INFO_1(string sharename, uint sharetype, string remark)
            {
                this.shi1_netname = sharename;
                this.shi1_type = sharetype;
                this.shi1_remark = remark;
            }
            public override string ToString()
            {
                return shi1_netname;
            }
        }

        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern int NetShareEnum(
             string ServerName,
             int level,
             ref IntPtr bufPtr,
             uint prefmaxlen,
             ref int entriesread,
             ref int totalentries,
             ref int resume_handle
             );

        [DllImport("Netapi32", CharSet = CharSet.Auto)]
        internal static extern int NetApiBufferFree(IntPtr Buffer);

        internal struct LSA_OBJECT_ATTRIBUTES
        {
            public UInt32 Length;
            public IntPtr RootDirectory;
            public UNICODE_STRING ObjectName;
            public UInt32 Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [DllImport("advapi32.dll")]
        internal static extern int LsaOpenPolicy(
           ref UNICODE_STRING SystemName,
           ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
           uint DesiredAccess,
           out IntPtr PolicyHandle
        );

        [DllImport("advapi32.dll")]
        internal static extern int LsaClose(IntPtr ObjectHandle);

        [StructLayout(LayoutKind.Sequential)]
        internal struct LSA_TRUST_INFORMATION
        {
            internal UNICODE_STRING Name;
            internal IntPtr Sid;
        }

        [DllImport("advapi32.dll")]
        internal static extern int LsaEnumerateTrustedDomains(
            IntPtr PolicyHandle,
            ref IntPtr EnumerationContext,
            out IntPtr Buffer,
            UInt32 PreferedMaximumLength,
            out UInt32 CountReturned
        );

        #endregion


        [DllImport("advapi32.dll")]
        internal static extern int LsaFreeMemory(IntPtr pBuffer);

        [DllImport("advapi32.dll")]
        internal static extern int LsaQueryForestTrustInformation(
            IntPtr PolicyHandle,
            ref UNICODE_STRING           TrustedDomainName,
            out IntPtr ForestTrustInfo
        );

        [StructLayout(LayoutKind.Sequential)]
        internal struct LSA_FOREST_TRUST_INFORMATION
        {
            public UInt32 RecordCount;
            public IntPtr Entries;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct LSA_FOREST_TRUST_DOMAIN_INFO {
            public IntPtr Sid;
            public UNICODE_STRING DnsName;
            public UNICODE_STRING NetbiosName;
        }
        [StructLayout(LayoutKind.Sequential)]
        internal struct LSA_FOREST_TRUST_BINARY_DATA {
            public UInt32 Length;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Explicit)]
        internal struct LSA_FOREST_TRUST_RECORD {
            [FieldOffset(0)] 
            public UInt32 Flags;
            [FieldOffset(4)]
            public UInt32 ForestTrustType;
            [FieldOffset(8)]
            public Int64 Time;
            [FieldOffset(16)]
            public UNICODE_STRING TopLevelName;
            [FieldOffset(16)]
            public LSA_FOREST_TRUST_DOMAIN_INFO DomainInfo;
            [FieldOffset(16)]
            public LSA_FOREST_TRUST_BINARY_DATA Data;
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern int LsaLookupSids(
            IntPtr PolicyHandle,
            int Count,
            IntPtr ptrEnumBuf,
            out IntPtr ptrDomainList,
            out IntPtr ptrNameList
         );

        [DllImport("advapi32")]
        internal static extern int LsaLookupNames(
            IntPtr PolicyHandle,
            uint Count,
            UNICODE_STRING[] Names,
            out IntPtr ReferencedDomains,
            out IntPtr Sids
        );

        [StructLayout(LayoutKind.Sequential)]
        internal struct LSA_REFERENCED_DOMAIN_LIST
        {
            public int Entries;
            public IntPtr Domains;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_TRANSLATED_NAME
        {
			public SID_NAME_USE Use;
            public UNICODE_STRING Name;
            public int DomainIndex;
        }

        [SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        public static SecurityIdentifier GetSidFromDomainName(string server, string domainToResolve)
        {
            NativeMethods.UNICODE_STRING us = new NativeMethods.UNICODE_STRING();
            NativeMethods.LSA_OBJECT_ATTRIBUTES loa = new NativeMethods.LSA_OBJECT_ATTRIBUTES();
            us.Initialize(server);
            IntPtr PolicyHandle = IntPtr.Zero;
            int ret = NativeMethods.LsaOpenPolicy(ref us, ref loa, 0x00000800, out PolicyHandle);
            if (ret != 0)
            {
                Trace.WriteLine("LsaOpenPolicy 0x" + ret.ToString("x"));
                return null;
            }
            try
            {
                UNICODE_STRING usdomain = new UNICODE_STRING();
                usdomain.Initialize(domainToResolve);
                IntPtr ReferencedDomains, Sids;
                ret = LsaLookupNames(PolicyHandle, 1, new UNICODE_STRING[] { usdomain }, out ReferencedDomains, out Sids);
                if (ret != 0)
                {
                    Trace.WriteLine("LsaLookupNames 0x" + ret.ToString("x"));
                    return null;
                }
                try
                {
                    LSA_REFERENCED_DOMAIN_LIST domainList = (LSA_REFERENCED_DOMAIN_LIST)Marshal.PtrToStructure(ReferencedDomains, typeof(LSA_REFERENCED_DOMAIN_LIST));
                    if (domainList.Entries > 0)
                    {
                        LSA_TRUST_INFORMATION trustInfo = (LSA_TRUST_INFORMATION)Marshal.PtrToStructure(domainList.Domains, typeof(LSA_TRUST_INFORMATION));
                        return new SecurityIdentifier(trustInfo.Sid);
                    }
                }
                finally
                {
                    LsaFreeMemory(ReferencedDomains);
                    LsaFreeMemory(Sids);
                }
            }
            finally
            {
                NativeMethods.LsaClose(PolicyHandle);
            }
            return null;
        }

        //public static string GetNameFromSID(string server, SecurityIdentifier sidToResolve)
        //{
        //    NativeMethods.UNICODE_STRING us = new NativeMethods.UNICODE_STRING();
        //    NativeMethods.LSA_OBJECT_ATTRIBUTES loa = new NativeMethods.LSA_OBJECT_ATTRIBUTES();
        //    us.Initialize(server);
        //    IntPtr PolicyHandle = IntPtr.Zero;
        //    int ret = NativeMethods.LsaOpenPolicy(ref us, ref loa, 0x00000800, out PolicyHandle);
        //    if (ret != 0)
        //    {
        //        Trace.WriteLine("LsaOpenPolicy 0x" + ret.ToString("x"));
        //        return null;
        //    }
        //    try
        //    {
        //        byte[] Sid = new byte[sidToResolve.BinaryLength];
        //        sidToResolve.GetBinaryForm(Sid, 0);
        //        GCHandle handle = GCHandle.Alloc(Sid, GCHandleType.Pinned);
        //        IntPtr array = handle.AddrOfPinnedObject();
        //        GCHandle handlearray = GCHandle.Alloc(array, GCHandleType.Pinned);
        //        IntPtr enumBuffer = IntPtr.Zero;
        //        IntPtr ReferencedDomains, NameList;
        //        ret = LsaLookupSids(PolicyHandle, 1, handlearray.AddrOfPinnedObject(), out ReferencedDomains, out NameList);
        //        handle.Free();
        //        handlearray.Free();
        //        if (ret != 0)
        //        {
        //            Trace.WriteLine("LsaLookupSids 0x" + ret.ToString("x"));
        //            return null;
        //        }
        //        try
        //        {
        //            LSA_REFERENCED_DOMAIN_LIST domainList = (LSA_REFERENCED_DOMAIN_LIST)Marshal.PtrToStructure(ReferencedDomains, typeof(LSA_REFERENCED_DOMAIN_LIST));
        //            if (domainList.Entries == 0)
        //                return null;
        //            LSA_TRUST_INFORMATION trustInfo = (LSA_TRUST_INFORMATION)Marshal.PtrToStructure(domainList.Domains, typeof(LSA_TRUST_INFORMATION));
        //            LSA_TRANSLATED_NAME translatedName = (LSA_TRANSLATED_NAME)Marshal.PtrToStructure(NameList, typeof(LSA_TRANSLATED_NAME));
        //            return trustInfo.Name.ToString() + "\\" + translatedName.Name;
        //        }
        //        finally
        //        {
        //            LsaFreeMemory(ReferencedDomains);
        //            LsaFreeMemory(NameList);
        //        }
        //    }
        //    finally
        //    {
        //        NativeMethods.LsaClose(PolicyHandle);
        //    }
        //}

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

        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern int DsGetDcName
        (
            [MarshalAs(UnmanagedType.LPWStr)]
            string ComputerName,
            [MarshalAs(UnmanagedType.LPWStr)]
            string DomainName,
            [In] IntPtr DomainGuid,
            [MarshalAs(UnmanagedType.LPWStr)]
            string SiteName,
            uint Flags,
            out IntPtr pDOMAIN_CONTROLLER_INFO
        );

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		public struct STAT_WORKSTATION_0
		{
			public long StatisticsStartTime;
			public long BytesReceived;
			public long SmbsReceived;
			public long PagingReadBytesRequested;
			public long NonPagingReadBytesRequested;
			public long CacheReadBytesRequested;
			public long NetworkReadBytesRequested;
			public long BytesTransmitted;
			public long SmbsTransmitted;
			public long PagingWriteBytesRequested;
			public long NonPagingWriteBytesRequested;
			public long CacheWriteBytesRequested;
			public long NetworkWriteBytesRequested;
			public uint InitiallyFailedOperations;
			public uint FailedCompletionOperations;
			public uint ReadOperations;
			public uint RandomReadOperations;
			public uint ReadSmbs;
			public uint LargeReadSmbs;
			public uint SmallReadSmbs;
			public uint WriteOperations;
			public uint RandomWriteOperations;
			public uint WriteSmbs;
			public uint LargeWriteSmbs;
			public uint SmallWriteSmbs;
			public uint RawReadsDenied;
			public uint RawWritesDenied;
			public uint NetworkErrors;
			public uint Sessions;
			public uint FailedSessions;
			public uint Reconnects;
			public uint CoreConnects;
			public uint Lanman20Connects;
			public uint Lanman21Connects;
			public uint LanmanNtConnects;
			public uint ServerDisconnects;
			public uint HungSessions;
			public uint UseCount;
			public uint FailedUseCount;
			public uint CurrentCommands;
		}

		[DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
		internal static extern uint NetStatisticsGet(
			[In, MarshalAs(UnmanagedType.LPWStr)] string server,
			[In, MarshalAs(UnmanagedType.LPWStr)] string service,
			int level,
			int options,
			out IntPtr bufptr);

		[SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.UnmanagedCode)]
		public static DateTime GetStartupTime(string server)
		{
			IntPtr buffer = IntPtr.Zero;
			uint ret = NetStatisticsGet(server, "LanmanWorkstation", 0, 0, out buffer);
			if (ret != 0)
			{
				Trace.WriteLine("GetStartupTime " + server + " returned " + ret);
				return DateTime.MinValue;
			}
			try
			{
				STAT_WORKSTATION_0 data = (STAT_WORKSTATION_0)Marshal.PtrToStructure(buffer, typeof(STAT_WORKSTATION_0));
				return DateTime.FromFileTime(data.StatisticsStartTime);
			}
			finally
			{
				NetApiBufferFree(buffer);
			}
		}

		[DllImport("winspool.drv", CharSet = CharSet.Unicode, EntryPoint = "OpenPrinterW", SetLastError = true)]
		internal static extern bool OpenPrinter(string pPrinterName, out IntPtr phPrinter, IntPtr pDefault);

		[DllImport("winspool.drv", CharSet = CharSet.Unicode, EntryPoint = "ClosePrinter", SetLastError = true)]
		internal static extern bool ClosePrinter(IntPtr phPrinter);

		[DllImport("Netapi32.dll", CallingConvention = CallingConvention.Winapi, SetLastError = true, CharSet = CharSet.Auto)]
		internal static extern uint DsEnumerateDomainTrusts(string ServerName,
									uint Flags,
									out IntPtr Domains,
									out uint DomainCount);

		[Flags]
		internal enum DS_DOMAIN_TRUST_TYPE : uint
		{
			DS_DOMAIN_IN_FOREST = 0x0001,  // Domain is a member of the forest
			DS_DOMAIN_DIRECT_OUTBOUND = 0x0002,  // Domain is directly trusted
			DS_DOMAIN_TREE_ROOT = 0x0004,  // Domain is root of a tree in the forest
			DS_DOMAIN_PRIMARY = 0x0008,  // Domain is the primary domain of queried server
			DS_DOMAIN_NATIVE_MODE = 0x0010,  // Primary domain is running in native mode
			DS_DOMAIN_DIRECT_INBOUND = 0x0020,   // Domain is directly trusting
			ALL = 0x003F,
		}

		[StructLayout(LayoutKind.Sequential)]
		internal struct DS_DOMAIN_TRUSTS
		{
			[MarshalAs(UnmanagedType.LPTStr)]
			public string NetbiosDomainName;
			[MarshalAs(UnmanagedType.LPTStr)]
			public string DnsDomainName;
			public uint Flags;
			public uint ParentIndex;
			public uint TrustType;
			public uint TrustAttributes;
			public IntPtr DomainSid;
			public Guid DomainGuid;
		}

    }

}
