//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//

using System;
using System.Runtime.InteropServices;

namespace PingCastle.RPC
{
    internal class NativeMethods
    {
        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingFromStringBindingW",
            CallingConvention = CallingConvention.StdCall,
            CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern int RpcBindingFromStringBinding(string bindingString, out IntPtr lpBinding);

        [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
            CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern IntPtr NdrClientCall2x64(IntPtr pMIDL_STUB_DESC, IntPtr formatString, ref IntPtr Handle);

        [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
            CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern IntPtr NdrClientCall2x64(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr intptrServer, int flag, ref PingCastle.RPC.nrpc.NETLOGON_TRUSTED_DOMAIN_ARRAY output);

        [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
            CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern IntPtr NdrClientCall2x64(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr intptrSystemName, ref PingCastle.RPC.lsa.LSAPR_OBJECT_ATTRIBUTES objectAttributes, uint DesiredAccess, out IntPtr PolicyHandle);

        [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
            CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern IntPtr NdrClientCall2x64(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr PolicyHandle, uint InformationClass, out IntPtr IntPtrPolicyInformation);

        [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
            CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern IntPtr NdrClientCall2x64(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr PolicyHandle, PingCastle.RPC.lsa.LSAPR_SID_ENUM_BUFFER enumBuffer, out IntPtr IntPtrReferencedDomains, IntPtr IntPtrTranslatedNames, uint LookupLevel, out uint MappedCount);

        [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
            CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern IntPtr NdrClientCall2x64(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr intptrServer, out IntPtr ServerHandle, uint DesiredAccess);

        [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
            CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern IntPtr NdrClientCall2x64(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr ServerHandle, ref IntPtr EnumerationContext, out IntPtr IntptrBuffer, uint PreferedMaximumLength, out uint CountReturned);

        [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
            CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern IntPtr NdrClientCall2x64(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr ServerHandle, PingCastle.NativeMethods.UNICODE_STRING NameString, out IntPtr sid);

        [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
            CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern IntPtr NdrClientCall2x64(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr ServerHandle, int DesiredAccess, byte[] sid, out IntPtr DomainHandle);

        [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
            CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern IntPtr NdrClientCall2x64(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr DomainHandle, ref IntPtr EnumerationContext, int UserAccountControl, out IntPtr IntptrBuffer, int PreferedMaximumLength, ref uint CountReturned);

        [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
            CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern IntPtr NdrClientCall2x86(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr args);

        [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
            CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern IntPtr NdrClientCall2x64(IntPtr intPtr1, IntPtr intPtr2, string pPrinterName, out IntPtr pHandle, string pDatatype, ref rprn.DEVMODE_CONTAINER pDevModeContainer, int AccessRequired);

        [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
            CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern IntPtr NdrClientCall2x64(IntPtr intPtr1, IntPtr intPtr2, IntPtr hPrinter, uint fdwFlags, uint fdwOptions, string pszLocalMachine, uint dwPrinterLocal, IntPtr intPtr3);

        [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
            CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern IntPtr NdrClientCall2x64(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr Handle, ref PingCastle.RPC.OxidBindings.COMVERSION i1, out System.IntPtr i2, ref uint i3);

        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingFree", CallingConvention = CallingConvention.StdCall,
            CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern int RpcBindingFree(ref IntPtr lpString);

        //#region RpcStringBindingCompose

        [DllImport("Rpcrt4.dll", EntryPoint = "RpcStringBindingComposeW", CallingConvention = CallingConvention.StdCall,
            CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern int RpcStringBindingCompose(
            string ObjUuid,
            string ProtSeq,
            string NetworkAddr,
            string Endpoint,
            string Options,
            out IntPtr lpBindingString
        );

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct SEC_WINNT_AUTH_IDENTITY
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string User;
            public int UserLength;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string Domain;
            public int DomainLength;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string Password;
            public int PasswordLength;
            public int Flags;
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct RPC_SECURITY_QOS
        {
            public int Version;
            public int Capabilities;
            public int IdentityTracking;
            public int ImpersonationType;
        };

        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingSetAuthInfoW", CallingConvention = CallingConvention.StdCall,
            CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern int RpcBindingSetAuthInfo(IntPtr Binding,
                                                           string ServerPrincName,
                                                           uint AuthnLevel,
                                                           uint AuthnSvc,
                                                           IntPtr identity,
                                                           uint AuthzSvc);

        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingSetAuthInfoExW", CallingConvention = CallingConvention.StdCall,
            CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern int RpcBindingSetAuthInfoEx(IntPtr lpBinding,
                                                             string ServerPrincName,
                                                             uint AuthnLevel,
                                                             uint AuthnSvc,
                                                             ref SEC_WINNT_AUTH_IDENTITY AuthIdentity,
                                                             uint AuthzSvc,
                                                             ref RPC_SECURITY_QOS SecurityQOS);

        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingSetAuthInfoW", CallingConvention = CallingConvention.StdCall,
            CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern int RpcBindingSetAuthInfo(IntPtr lpBinding,
                                                           string ServerPrincName,
                                                           uint AuthnLevel,
                                                           uint AuthnSvc,
                                                           ref SEC_WINNT_AUTH_IDENTITY AuthIdentity,
                                                           uint AuthzSvc);

        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingSetAuthInfoW", CallingConvention = CallingConvention.StdCall,
            CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern int RpcBindingSetAuthInfo(IntPtr lpBinding,
                                                           string ServerPrincName,
                                                           uint AuthnLevel,
                                                           uint AuthnSvc,
                                                           UIntPtr pointer,
                                                           uint AuthzSvc);

        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingSetOption", CallingConvention = CallingConvention.StdCall, SetLastError = false)]
        internal static extern int RpcBindingSetOption(IntPtr Binding, uint Option, uint OptionValue);

        [DllImport("Rpcrt4.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern int RpcEpResolveBinding(IntPtr Binding, IntPtr RpcClientInterface);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern IntPtr GetSidSubAuthority(IntPtr sid, uint subAuthorityIndex);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern IntPtr GetSidSubAuthorityCount(IntPtr psid);
    }
}