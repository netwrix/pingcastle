//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using System.Security.Principal;
using System.Text;

namespace PingCastle.RPC
{
    public enum TypeOfEnumeration
    {
        Samr,
        Lsa,
    }

    public class NullSessionTester
    {
        public delegate void Enumerate(NTAccount account);

        public Enumerate EnumerateCallback { get; set; }
        public string Server { get; set; }
        public uint RPCTimeOut { get; set; }

        public NullSessionTester(string server, Enumerate enumerateCallback = null)
        {
            Server = server;
            EnumerateCallback = enumerateCallback;
        }

        public bool EnumerateAccount(int MaximumNumber = int.MaxValue)
        {
            if (EnumerateAccount(TypeOfEnumeration.Samr, MaximumNumber))
                return true;
            return EnumerateAccount(TypeOfEnumeration.Lsa, MaximumNumber);
        }

        public bool EnumerateAccount(TypeOfEnumeration method, int MaximumNumber = int.MaxValue)
        {
            if (method == TypeOfEnumeration.Samr)
            {
                return EnumerateAccountUsingSamr(method, MaximumNumber);
            }
            else if (method == TypeOfEnumeration.Lsa)
            {
                return EnumerateAccountUsingLsa(method, MaximumNumber);
            }
            return false;
        }

        [SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        private bool EnumerateAccountUsingLsa(TypeOfEnumeration method, int MaximumNumber)
        {
            Trace.WriteLine("EnumerateAccountUsingLsa");
            int UserEnumerated = 0; 
            Int32 returnCode;
            IntPtr PolicyHandle = IntPtr.Zero;
            lsa lsa = new lsa();
            lsa.RPCTimeOut = this.RPCTimeOut;
            returnCode = lsa.LsarOpenPolicy(Server, 0x00000801, out PolicyHandle);
            if (returnCode != 0)
            {
                Trace.WriteLine("LsarOpenPolicy " + returnCode);
                return false;
            }
            try
            {
                LSA_DOMAIN_INFORMATION PolicyInformation;
                returnCode = lsa.LsarQueryInformationPolicy(PolicyHandle, 5, out PolicyInformation);
                if (returnCode != 0)
                {
                    Trace.WriteLine("LsarQueryInformationPolicy " + returnCode);
                    return false;
                }
                uint currentRid = 500;
                int iteration = 0;
                // allows 10*1000 sid non resolved
                int retrycount = 0;
                while ((returnCode == 0 || returnCode == 0x00000107 || (retrycount < 10 && returnCode == -1073741709)) && UserEnumerated < MaximumNumber)
                {
                    Trace.WriteLine("LsarLookupSids iteration " + iteration++);
                    SecurityIdentifier[] enumBuffer = new SecurityIdentifier[1000];
                    for (int i = 0; i < enumBuffer.Length; i++)
                    {
                        enumBuffer[i] = BuildSIDFromDomainSidAndRid(PolicyInformation.DomainSid, currentRid++);
                    }
                    UInt32 MappedCount;
                    LSA_LOOKUP_RESULT[] LookupResult;
                    returnCode = lsa.LsarLookupSids(PolicyHandle, enumBuffer, out LookupResult, 2, out MappedCount);
                    if (returnCode == 0 || returnCode == 0x00000107)
                    {
                        retrycount = 0;
                        for (int i = 0; i < enumBuffer.Length && UserEnumerated < MaximumNumber; i++)
                        {
                            if (LookupResult[i].Use == SID_NAME_USE.SidTypeUser && !String.IsNullOrEmpty(LookupResult[i].TranslatedName))
                            {
                                UserEnumerated++;
                                Trace.WriteLine("User:" + LookupResult[i].TranslatedName);
                                if (EnumerateCallback != null)
                                {
                                    EnumerateCallback(new NTAccount(LookupResult[i].DomainName, LookupResult[i].TranslatedName));
                                }
                            }
                        }
                    }
                    else
                    {
                        retrycount++;
                        Trace.WriteLine("LsarLookupSids " + returnCode);
                    }
                }
            }
            finally
            {
                returnCode = lsa.LsarClose(ref PolicyHandle);
            }
            Trace.WriteLine("EnumerateAccountUsingLsa done");
            return UserEnumerated > 0;
        }

        [SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        private bool EnumerateAccountUsingSamr(TypeOfEnumeration method, int MaximumNumber)
        {
            Trace.WriteLine("EnumerateAccountUsingSamr"); 
            int UserEnumerated = 0;
            IntPtr ServerHandle = IntPtr.Zero;
            samr sam = new samr();
            sam.RPCTimeOut = this.RPCTimeOut;
            Int32 returnCode;
            returnCode = sam.SamrConnect(Server, out ServerHandle, 0x20030);
            if (returnCode != 0)
            {
                Trace.WriteLine("SamrConnect " + returnCode);
                return false;
            }
            try
            {
                IntPtr enumerationContext = IntPtr.Zero;
                SAMR_ENUMERATION_ENTRY[] Buffer = null;
                UInt32 CountReturned = 0;
                returnCode = sam.SamrEnumerateDomainsInSamServer(ServerHandle, ref enumerationContext, out Buffer, 10000, out CountReturned);
                if (returnCode != 0)
                {
                    Trace.WriteLine("SamrEnumerateDomainsInSamServer " + returnCode);
                    return false;
                }
                for (ulong i = 0; i < CountReturned; i++)
                {
                    Trace.WriteLine("Domain:" + Buffer[i].Name);
                    SecurityIdentifier DomainId;
                    IntPtr DomainHandle = IntPtr.Zero;
                    IntPtr enumerationContextUser = IntPtr.Zero;
                    SAMR_ENUMERATION_ENTRY[] EnumerationBuffer = null;
                    UInt32 UserCount = 0;
                    returnCode = sam.SamrLookupDomainInSamServer(ServerHandle, Buffer[i].Name, out DomainId);
                    if (returnCode < 0)
                    {
                        Trace.WriteLine("SamrLookupDomainInSamServer " + returnCode);
                        continue;
                    }
                    returnCode = sam.SamrOpenDomain(ServerHandle, 0x100, DomainId, out DomainHandle);
                    if (returnCode < 0)
                    {
                        Trace.WriteLine("SamrOpenDomain " + returnCode);
                        continue;
                    }
                    try
                    {
                        int iteration = 0;
                        returnCode = 0x00000105;
                        while (returnCode == 0x00000105 && UserEnumerated < MaximumNumber)
                        {
                            Trace.WriteLine("SamrEnumerateUsersInDomain iteration " + iteration++);
                            returnCode = sam.SamrEnumerateUsersInDomain(DomainHandle, ref enumerationContextUser, 0, out EnumerationBuffer, 10000, out UserCount);
                            if ((returnCode == 0 || returnCode == 0x00000105) && EnumerationBuffer != null)
                            {
                                for (int j = 0; j < EnumerationBuffer.Length && UserEnumerated++ < MaximumNumber; j++)
                                {
                                    Trace.WriteLine("User:" + EnumerationBuffer[j].Name);
                                    if (EnumerateCallback != null)
                                    {
                                        EnumerateCallback(new NTAccount(Buffer[i].Name, EnumerationBuffer[j].Name));
                                    }
                                }
                            }
                        }
                        Trace.WriteLine("SamrEnumerateUsersInDomain " + returnCode);
                    }
                    finally
                    {
                        sam.SamrCloseHandle(ref DomainHandle);
                    }
                }
            }
            finally
            {
                sam.SamrCloseHandle(ref ServerHandle);
            }
            Trace.WriteLine("EnumerateAccountUsingSamr done"); 
            return UserEnumerated > 0;
        }

        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        public static SecurityIdentifier BuildSIDFromDomainSidAndRid(SecurityIdentifier DomainSid, UInt32 Rid)
        {
            byte[] sidByteForm = new byte[SecurityIdentifier.MaxBinaryLength];
            DomainSid.GetBinaryForm(sidByteForm, 0);
            GCHandle handle = GCHandle.Alloc(sidByteForm, GCHandleType.Pinned);
            IntPtr sidIntPtr = handle.AddrOfPinnedObject();

            IntPtr SubAuthorityCountIntPtr = NativeMethods.GetSidSubAuthorityCount(sidIntPtr);
            byte SubAuthorityCount = Marshal.ReadByte(SubAuthorityCountIntPtr);
            Marshal.WriteByte(SubAuthorityCountIntPtr, ++SubAuthorityCount);

            IntPtr SubAuthorityIntPtr = NativeMethods.GetSidSubAuthority(sidIntPtr, (uint)SubAuthorityCount - 1);
            Marshal.WriteInt32(SubAuthorityIntPtr, (int)Rid);
            SecurityIdentifier output = new SecurityIdentifier(sidIntPtr);
            handle.Free();
            return output;
        }


    }
}
