//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace PingCastle.RPC
{
    internal class NativeMethods
    {
        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingFromStringBindingW",
            CallingConvention = CallingConvention.StdCall,
            CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern Int32 RpcBindingFromStringBinding(String bindingString, out IntPtr lpBinding);

		[DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
		   CharSet = CharSet.Unicode, SetLastError = false)]
		internal static extern IntPtr NdrClientCall2x64(IntPtr pMIDL_STUB_DESC, IntPtr formatString, ref IntPtr Handle);

		[DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
		   CharSet = CharSet.Unicode, SetLastError = false)]
		internal static extern IntPtr NdrClientCall2x64(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr intptrServer, int flag, ref PingCastle.RPC.nrpc.NETLOGON_TRUSTED_DOMAIN_ARRAY output);
		
		[DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
		   CharSet = CharSet.Unicode, SetLastError = false)]
		internal static extern IntPtr NdrClientCall2x64(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr intptrSystemName, ref PingCastle.RPC.lsa.LSAPR_OBJECT_ATTRIBUTES objectAttributes, UInt32 DesiredAccess, out IntPtr PolicyHandle);

		[DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
		   CharSet = CharSet.Unicode, SetLastError = false)]
		internal static extern IntPtr NdrClientCall2x64(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr PolicyHandle, UInt32 InformationClass, out IntPtr IntPtrPolicyInformation);

		[DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
		   CharSet = CharSet.Unicode, SetLastError = false)]
		internal static extern IntPtr NdrClientCall2x64(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr PolicyHandle, PingCastle.RPC.lsa.LSAPR_SID_ENUM_BUFFER enumBuffer, out IntPtr IntPtrReferencedDomains, IntPtr IntPtrTranslatedNames, UInt32 LookupLevel, out UInt32 MappedCount);

		[DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
		   CharSet = CharSet.Unicode, SetLastError = false)]
		internal static extern IntPtr NdrClientCall2x64(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr intptrServer, out IntPtr ServerHandle, UInt32 DesiredAccess);

		[DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
		   CharSet = CharSet.Unicode, SetLastError = false)]
		internal static extern IntPtr NdrClientCall2x64(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr ServerHandle, ref IntPtr EnumerationContext, out IntPtr IntptrBuffer, UInt32 PreferedMaximumLength, out UInt32 CountReturned);

		[DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
		   CharSet = CharSet.Unicode, SetLastError = false)]
		internal static extern IntPtr NdrClientCall2x64(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr ServerHandle, PingCastle.NativeMethods.UNICODE_STRING NameString, out IntPtr sid);

		[DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
		   CharSet = CharSet.Unicode, SetLastError = false)]
		internal static extern IntPtr NdrClientCall2x64(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr ServerHandle, Int32 DesiredAccess, byte[] sid, out IntPtr DomainHandle);

		[DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
		   CharSet = CharSet.Unicode, SetLastError = false)]
		internal static extern IntPtr NdrClientCall2x64(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr DomainHandle, ref IntPtr EnumerationContext, Int32 UserAccountControl, out IntPtr IntptrBuffer, Int32 PreferedMaximumLength, ref UInt32 CountReturned);

        [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
            CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern IntPtr NdrClientCall2x86(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr args);

		[DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
			CharSet = CharSet.Unicode, SetLastError = false)]
		internal static extern IntPtr NdrClientCall2x64(IntPtr intPtr1, IntPtr intPtr2, string pPrinterName, out IntPtr pHandle, string pDatatype, ref rprn.DEVMODE_CONTAINER pDevModeContainer, int AccessRequired);

		[DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
			CharSet = CharSet.Unicode, SetLastError = false)]
		internal static extern IntPtr NdrClientCall2x64(IntPtr intPtr1, IntPtr intPtr2, IntPtr hPrinter, uint fdwFlags, uint fdwOptions, string pszLocalMachine, uint dwPrinterLocal, IntPtr intPtr3);

        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingFree", CallingConvention = CallingConvention.StdCall,
            CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern Int32 RpcBindingFree(ref IntPtr lpString);

        //#region RpcStringBindingCompose

        [DllImport("Rpcrt4.dll", EntryPoint = "RpcStringBindingComposeW", CallingConvention = CallingConvention.StdCall,
            CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern Int32 RpcStringBindingCompose(
            String ObjUuid, String ProtSeq, String NetworkAddr, String Endpoint, String Options,
            out IntPtr lpBindingString
            );

        [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
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
            public Int32 Version;
            public Int32 Capabilities;
            public Int32 IdentityTracking;
            public Int32 ImpersonationType;
        };

        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingSetAuthInfoExW", CallingConvention = CallingConvention.StdCall,
            CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern Int32 RpcBindingSetAuthInfoEx(IntPtr lpBinding, string ServerPrincName,
                                           UInt32 AuthnLevel, UInt32 AuthnSvc, ref SEC_WINNT_AUTH_IDENTITY AuthIdentity, UInt32 AuthzSvc, ref RPC_SECURITY_QOS SecurityQOS);
        
        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingSetAuthInfoW", CallingConvention = CallingConvention.StdCall,
            CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern Int32 RpcBindingSetAuthInfo(IntPtr lpBinding, string ServerPrincName,
                                           UInt32 AuthnLevel, UInt32 AuthnSvc, ref SEC_WINNT_AUTH_IDENTITY AuthIdentity, UInt32 AuthzSvc);

        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingSetAuthInfoW", CallingConvention = CallingConvention.StdCall,
            CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern Int32 RpcBindingSetAuthInfo(IntPtr lpBinding, string ServerPrincName,
                                           UInt32 AuthnLevel, UInt32 AuthnSvc, UIntPtr pointer, UInt32 AuthzSvc);

        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingSetOption", CallingConvention = CallingConvention.StdCall,SetLastError= false)]
        internal static extern Int32 RpcBindingSetOption(IntPtr Binding,UInt32 Option, UInt32 OptionValue);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern IntPtr GetSidSubAuthority(IntPtr sid, UInt32 subAuthorityIndex);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern IntPtr GetSidSubAuthorityCount(IntPtr psid);

	}
}
