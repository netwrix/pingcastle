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
using System.Security.Principal;
using System.Text;

namespace PingCastle
{
    public class NativeMethods
    {
        #region PInvoke Signatures

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
        const int ERROR_INVALID_FLAGS = 1004;

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

        [EnvironmentPermissionAttribute(SecurityAction.Demand, Unrestricted = true)]
        public static string ConvertSIDToNameWithWindowsAPI(string sidstring, string server, out string referencedDomain)
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

        // used for local admins scanner
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

        // used in share scanner
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
        internal static extern uint LsaOpenPolicy(
           ref UNICODE_STRING SystemName,
           ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
           uint DesiredAccess,
           out IntPtr PolicyHandle
        );

        [DllImport("advapi32.dll")]
        internal static extern uint LsaClose(IntPtr ObjectHandle);

        [StructLayout(LayoutKind.Sequential)]
        internal struct LSA_TRUST_INFORMATION
        {
            internal UNICODE_STRING Name;
            internal IntPtr Sid;
        }

        #endregion


        [DllImport("advapi32.dll")]
        internal static extern int LsaFreeMemory(IntPtr pBuffer);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern uint LsaLookupSids(
            IntPtr PolicyHandle,
            int Count,
            IntPtr ptrEnumBuf,
            out IntPtr ptrDomainList,
            out IntPtr ptrNameList
         );

        [DllImport("advapi32")]
        internal static extern uint LsaLookupNames(
            IntPtr PolicyHandle,
            int Count,
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

        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_TRANSLATED_SID
        {
            public SID_NAME_USE Use;
            public uint RelativeId;
            public int DomainIndex;
        }

        [SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        public static SecurityIdentifier GetSidFromDomainNameWithWindowsAPI(string server, string domainToResolve)
        {
            NativeMethods.UNICODE_STRING us = new NativeMethods.UNICODE_STRING();
            NativeMethods.LSA_OBJECT_ATTRIBUTES loa = new NativeMethods.LSA_OBJECT_ATTRIBUTES();
            us.Initialize(server);
            IntPtr PolicyHandle = IntPtr.Zero;
            uint ret = NativeMethods.LsaOpenPolicy(ref us, ref loa, 0x00000800, out PolicyHandle);
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

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WKSTA_INFO_100
        {
            public int platform_id;
            public string computer_name;
            public string lan_group;
            public int ver_major;
            public int ver_minor;
        }

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern uint NetWkstaGetInfo(
                string servername,
                int level,
                out IntPtr bufptr);

        [SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        public static string GetComputerVersion(string server)
        {
            IntPtr buffer = IntPtr.Zero;
            uint ret = NetWkstaGetInfo(server, 100, out buffer);
            if (ret != 0)
            {
                Trace.WriteLine("GetComputerVersion " + server + " returned " + ret);
                return "not found";
            }
            try
            {
                WKSTA_INFO_100 data = (WKSTA_INFO_100)Marshal.PtrToStructure(buffer, typeof(WKSTA_INFO_100));
                string version = data.ver_major.ToString() + "." + data.ver_minor.ToString();
                return version;
            }
            finally
            {
                NetApiBufferFree(buffer);
            }
        }

        [DllImport("Netapi32", CharSet = CharSet.Auto)]
        internal static extern int NetApiBufferFree(IntPtr Buffer);


        [DllImport("Dnsapi.dll", CharSet = CharSet.Unicode, EntryPoint = "DnsQuery_W")]
        internal static extern int DnsQuery([In] string recordName, [In] short recordType, [In] int options, [In] IntPtr servers, out IntPtr dnsResultList, [Out] IntPtr reserved);

        [DllImport("Dnsapi.dll", CharSet = CharSet.Unicode)]
        internal static extern void DnsRecordListFree([In] IntPtr dnsResultList, [In] bool dnsFreeType);

        [DllImport("Dnsapi.dll", SetLastError = true, EntryPoint = "DnsWriteQuestionToBuffer_W", CharSet = CharSet.Unicode)]
        internal static extern bool DnsWriteQuestionToBuffer(
            byte[] buffer,
            ref int bufferSize,
            string name,
            ushort wType,
            ushort Xid,
            bool fRecursionDesired);

        [DllImport("Dnsapi.dll", SetLastError = true, EntryPoint = "DnsExtractRecordsFromMessage_W", CharSet = CharSet.Unicode)]
        internal static extern bool DnsExtractRecordsFromMessage(
            byte[] message,
            int messageLength,
            out IntPtr ppRecords);

        [DllImport("Crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CryptDecodeObject([In] uint dwCertEncodingType, [In] [MarshalAs(UnmanagedType.LPStr)] string lpszStructType, [In] byte[] pbEncoded, [In] uint cbEncoded, [In] uint dwFlags, [Out] IntPtr pvStructInfo, [In] [Out] ref uint pcbStructInfo);

        public struct CERT_TEMPLATE_EXT
        {
            [MarshalAs(UnmanagedType.LPStr)]
            public string pszObjId;

            public uint dwMajorVersion;

            public bool fMinorVersion;

            public uint dwMinorVersion;
        }

        #region convert command line to argc
        [DllImport("shell32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern IntPtr CommandLineToArgvW([MarshalAs(UnmanagedType.LPWStr)] string lpCmdLine, out int pNumArgs);

        [DllImport("kernel32.dll")]
        static extern IntPtr LocalFree(IntPtr hMem);

        private static string[] SplitArgsWindows(string unsplitArgumentLine)
        {
            int numberOfArgs;
            IntPtr ptrToSplitArgs;
            string[] splitArgs;

            ptrToSplitArgs = CommandLineToArgvW(unsplitArgumentLine, out numberOfArgs);

            // CommandLineToArgvW returns NULL upon failure.
            if (ptrToSplitArgs == IntPtr.Zero)
                throw new ArgumentException("Unable to split argument.", new Win32Exception());

            // Make sure the memory ptrToSplitArgs to is freed, even upon failure.
            try
            {
                splitArgs = new string[numberOfArgs];

                // ptrToSplitArgs is an array of pointers to null terminated Unicode strings.
                // Copy each of these strings into our split argument array.
                for (int i = 0; i < numberOfArgs; i++)
                    splitArgs[i] = Marshal.PtrToStringUni(
                        Marshal.ReadIntPtr(ptrToSplitArgs, i * IntPtr.Size));

                return splitArgs;
            }
            finally
            {
                // Free memory obtained by CommandLineToArgW.
                LocalFree(ptrToSplitArgs);
            }
        }

        public static string[] SplitArguments(string commandLine)
        {
            if (Environment.OSVersion.Platform == PlatformID.Win32NT)
            {
                return SplitArgsWindows(commandLine);
            }
            var parmChars = commandLine.ToCharArray();
            var inSingleQuote = false;
            var inDoubleQuote = false;
            for (var index = 0; index < parmChars.Length; index++)
            {
                if (parmChars[index] == '"' && !inSingleQuote)
                {
                    inDoubleQuote = !inDoubleQuote;
                    parmChars[index] = '\n';
                }
                if (parmChars[index] == '\'' && !inDoubleQuote)
                {
                    inSingleQuote = !inSingleQuote;
                    parmChars[index] = '\n';
                }
                if (!inSingleQuote && !inDoubleQuote && parmChars[index] == ' ')
                    parmChars[index] = '\n';
            }
            return (new string(parmChars)).Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries);
        }
        #endregion convert command line to argc
    }
}
