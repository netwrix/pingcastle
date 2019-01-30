//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using System.Text;

namespace PingCastle.RPC
{
    public abstract class rpcapi
    {

        private byte[] MIDL_ProcFormatString;
        private byte[] MIDL_TypeFormatString;
        private GCHandle procString;
        private GCHandle formatString;
        private GCHandle stub;
        private GCHandle faultoffsets;
        private GCHandle clientinterface;
        private GCHandle bindinghandle;
        private string PipeName;

        // important: keep a reference on delegate to avoid CallbackOnCollectedDelegate exception
        bind BindDelegate;
        unbind UnbindDelegate;
        allocmemory AllocateMemoryDelegate = AllocateMemory;
        freememory FreeMemoryDelegate = FreeMemory;

		public bool UseNullSession { get; set; }
        // 5 seconds
        public UInt32 RPCTimeOut = 5000;

        [StructLayout(LayoutKind.Sequential)]
        private struct COMM_FAULT_OFFSETS
        {
            public short CommOffset;
            public short FaultOffset;
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1049:TypesThatOwnNativeResourcesShouldBeDisposable"), StructLayout(LayoutKind.Sequential)]
        private struct GENERIC_BINDING_ROUTINE_PAIR
        {
            public IntPtr Bind;
            public IntPtr Unbind;
        }
        

        [StructLayout(LayoutKind.Sequential)]
        private struct RPC_VERSION
        {
            public ushort MajorVersion;
            public ushort MinorVersion;


            public static readonly RPC_VERSION INTERFACE_VERSION = new RPC_VERSION() { MajorVersion = 1, MinorVersion = 0 };
            public static readonly RPC_VERSION SYNTAX_VERSION = new RPC_VERSION() { MajorVersion = 2, MinorVersion = 0 };

            public RPC_VERSION(ushort InterfaceVersionMajor, ushort InterfaceVersionMinor)
            {
                MajorVersion = InterfaceVersionMajor;
                MinorVersion = InterfaceVersionMinor;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct RPC_SYNTAX_IDENTIFIER
        {
            public Guid SyntaxGUID;
            public RPC_VERSION SyntaxVersion;
        }

        

        [StructLayout(LayoutKind.Sequential)]
        private struct RPC_CLIENT_INTERFACE
        {
            public uint Length;
            public RPC_SYNTAX_IDENTIFIER InterfaceId;
            public RPC_SYNTAX_IDENTIFIER TransferSyntax;
            public IntPtr /*PRPC_DISPATCH_TABLE*/ DispatchTable;
            public uint RpcProtseqEndpointCount;
            public IntPtr /*PRPC_PROTSEQ_ENDPOINT*/ RpcProtseqEndpoint;
            public IntPtr Reserved;
            public IntPtr InterpreterInfo;
            public uint Flags;

            public static readonly Guid IID_SYNTAX = new Guid(0x8A885D04u, 0x1CEB, 0x11C9, 0x9F, 0xE8, 0x08, 0x00, 0x2B,
                                                              0x10,
                                                              0x48, 0x60);

            public RPC_CLIENT_INTERFACE(Guid iid, ushort InterfaceVersionMajor = 1, ushort InterfaceVersionMinor = 0)
            {
                Length = (uint)Marshal.SizeOf(typeof(RPC_CLIENT_INTERFACE));
                InterfaceId = new RPC_SYNTAX_IDENTIFIER() { SyntaxGUID = iid, SyntaxVersion = new RPC_VERSION(InterfaceVersionMajor, InterfaceVersionMinor) };
                TransferSyntax = new RPC_SYNTAX_IDENTIFIER() { SyntaxGUID = IID_SYNTAX, SyntaxVersion = RPC_VERSION.SYNTAX_VERSION };
                DispatchTable = IntPtr.Zero;
                RpcProtseqEndpointCount = 0u;
                RpcProtseqEndpoint = IntPtr.Zero;
                Reserved = IntPtr.Zero;
                InterpreterInfo = IntPtr.Zero;
                Flags = 0u;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIDL_STUB_DESC
        {
            public IntPtr /*RPC_CLIENT_INTERFACE*/ RpcInterfaceInformation;
            public IntPtr pfnAllocate;
            public IntPtr pfnFree;
            public IntPtr pAutoBindHandle;
            public IntPtr /*NDR_RUNDOWN*/ apfnNdrRundownRoutines;
            public IntPtr /*GENERIC_BINDING_ROUTINE_PAIR*/ aGenericBindingRoutinePairs;
            public IntPtr /*EXPR_EVAL*/ apfnExprEval;
            public IntPtr /*XMIT_ROUTINE_QUINTUPLE*/ aXmitQuintuple;
            public IntPtr pFormatTypes;
            public int fCheckBounds;
            /* Ndr library version. */
            public uint Version;
            public IntPtr /*MALLOC_FREE_STRUCT*/ pMallocFreeStruct;
            public int MIDLVersion;
            public IntPtr CommFaultOffsets;
            // New fields for version 3.0+
            public IntPtr /*USER_MARSHAL_ROUTINE_QUADRUPLE*/ aUserMarshalQuadruple;
            // Notify routines - added for NT5, MIDL 5.0
            public IntPtr /*NDR_NOTIFY_ROUTINE*/ NotifyRoutineTable;
            public IntPtr mFlags;
            // International support routines - added for 64bit post NT5
            public IntPtr /*NDR_CS_ROUTINES*/ CsRoutineTables;
            public IntPtr ProxyServerInfo;
            public IntPtr /*NDR_EXPR_DESC*/ pExprInfo;
            // Fields up to now present in win2000 release.

            public MIDL_STUB_DESC(IntPtr pFormatTypesPtr, IntPtr RpcInterfaceInformationPtr,
                                    IntPtr pfnAllocatePtr, IntPtr pfnFreePtr, IntPtr aGenericBindingRoutinePairsPtr)
            {
                pFormatTypes = pFormatTypesPtr;
                RpcInterfaceInformation = RpcInterfaceInformationPtr;
                CommFaultOffsets = IntPtr.Zero;
                pfnAllocate = pfnAllocatePtr;
                pfnFree = pfnFreePtr;
                pAutoBindHandle = IntPtr.Zero;
                apfnNdrRundownRoutines = IntPtr.Zero;
                aGenericBindingRoutinePairs = aGenericBindingRoutinePairsPtr;
                apfnExprEval = IntPtr.Zero;
                aXmitQuintuple = IntPtr.Zero;
                fCheckBounds = 1;
                Version = 0x50002u;
                pMallocFreeStruct = IntPtr.Zero;
                MIDLVersion = 0x8000253;
                aUserMarshalQuadruple = IntPtr.Zero;
                NotifyRoutineTable = IntPtr.Zero;
                mFlags = new IntPtr(0x00000001);
                CsRoutineTables = IntPtr.Zero;
                ProxyServerInfo = IntPtr.Zero;
                pExprInfo = IntPtr.Zero;
            }
        }

        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        protected void InitializeStub(Guid interfaceID, byte[] MIDL_ProcFormatString, byte[] MIDL_TypeFormatString, string pipe, ushort MajorVerson = 1, ushort MinorVersion = 0)
        {
            this.MIDL_ProcFormatString = MIDL_ProcFormatString;
            this.MIDL_TypeFormatString = MIDL_TypeFormatString;
            PipeName = pipe;
            procString = GCHandle.Alloc(this.MIDL_ProcFormatString, GCHandleType.Pinned);

            RPC_CLIENT_INTERFACE clientinterfaceObject = new RPC_CLIENT_INTERFACE(interfaceID, MajorVerson, MinorVersion);
            GENERIC_BINDING_ROUTINE_PAIR bindingObject = new GENERIC_BINDING_ROUTINE_PAIR();
            // important: keep a reference to avoid CallbakcOnCollectedDelegate Exception
            BindDelegate = Bind;
            UnbindDelegate = Unbind;
            bindingObject.Bind = Marshal.GetFunctionPointerForDelegate((bind)BindDelegate);
            bindingObject.Unbind = Marshal.GetFunctionPointerForDelegate((unbind)UnbindDelegate);

            faultoffsets = GCHandle.Alloc(new COMM_FAULT_OFFSETS() { CommOffset = -1, FaultOffset = -1 }, GCHandleType.Pinned);
            clientinterface = GCHandle.Alloc(clientinterfaceObject, GCHandleType.Pinned);
            formatString = GCHandle.Alloc(MIDL_TypeFormatString, GCHandleType.Pinned);
            bindinghandle = GCHandle.Alloc(bindingObject, GCHandleType.Pinned);

            MIDL_STUB_DESC stubObject = new MIDL_STUB_DESC(formatString.AddrOfPinnedObject(),
                                                            clientinterface.AddrOfPinnedObject(),
                                                            Marshal.GetFunctionPointerForDelegate(AllocateMemoryDelegate),
                                                            Marshal.GetFunctionPointerForDelegate(FreeMemoryDelegate),
                                                            bindinghandle.AddrOfPinnedObject());

            stub = GCHandle.Alloc(stubObject, GCHandleType.Pinned);
        }

        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        protected void freeStub()
        {
            procString.Free();
            faultoffsets.Free();
            clientinterface.Free();
            formatString.Free();
            bindinghandle.Free();
            stub.Free();
        }

        delegate IntPtr allocmemory(int size);
        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        protected static IntPtr AllocateMemory(int size)
        {
            IntPtr memory = Marshal.AllocHGlobal(size);
            //Trace.WriteLine("allocating " + memory.ToString());
            return memory;
        }

        delegate void freememory(IntPtr memory);
        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        protected static void FreeMemory(IntPtr memory)
        {
            //Trace.WriteLine("freeing " + memory.ToString());
            Marshal.FreeHGlobal(memory);
        }

        delegate IntPtr bind(IntPtr IntPtrserver);
        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        protected IntPtr Bind (IntPtr IntPtrserver)
        {
            string server = Marshal.PtrToStringUni(IntPtrserver);
            IntPtr bindingstring = IntPtr.Zero;
            IntPtr binding = IntPtr.Zero;
            Int32 status;

            Trace.WriteLine("Binding to " + server + " " + PipeName);
            status = NativeMethods.RpcStringBindingCompose(null, "ncacn_np", server, PipeName, null, out bindingstring);
            if (status != 0)
            {
                Trace.WriteLine("RpcStringBindingCompose failed with status 0x" + status.ToString("x"));
                return IntPtr.Zero;
            }
            status = NativeMethods.RpcBindingFromStringBinding(Marshal.PtrToStringUni(bindingstring), out binding);
            NativeMethods.RpcBindingFree(ref bindingstring);
            if (status != 0)
            {
                Trace.WriteLine("RpcBindingFromStringBinding failed with status 0x" + status.ToString("x"));
                return IntPtr.Zero;
            }
			if (UseNullSession)
			{
				// note: windows xp doesn't support user or domain = "" => return 0xE
				NativeMethods.SEC_WINNT_AUTH_IDENTITY identity = new NativeMethods.SEC_WINNT_AUTH_IDENTITY();
				identity.User = "";
				identity.UserLength = identity.User.Length * 2;
				identity.Domain = "";
				identity.DomainLength = identity.Domain.Length * 2;
				identity.Password = "";
				identity.Flags = 2;

				NativeMethods.RPC_SECURITY_QOS qos = new NativeMethods.RPC_SECURITY_QOS();
				qos.Version = 1;
				qos.ImpersonationType = 3;
				GCHandle qoshandle = GCHandle.Alloc(qos, GCHandleType.Pinned);

				// 9 = negotiate , 10 = ntlm ssp
				status = NativeMethods.RpcBindingSetAuthInfoEx(binding, server, 0, 9, ref identity, 0, ref qos);
				qoshandle.Free();
				if (status != 0)
				{
					Trace.WriteLine("RpcBindingSetAuthInfoEx failed with status 0x" + status.ToString("x"));
					Unbind(IntPtrserver, binding);
					return IntPtr.Zero;
				}
			}

            status = NativeMethods.RpcBindingSetOption(binding, 12, RPCTimeOut);
            if (status != 0)
            {
                Trace.WriteLine("RpcBindingSetOption failed with status 0x" + status.ToString("x"));
            }
            Trace.WriteLine("binding ok (handle=" + binding + ")");
            return binding;
        }

        delegate void unbind(IntPtr IntPtrserver, IntPtr hBinding);
        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        protected static void Unbind(IntPtr IntPtrserver, IntPtr hBinding)
        {
            string server = Marshal.PtrToStringUni(IntPtrserver);
            Trace.WriteLine("unbinding " + server);
            NativeMethods.RpcBindingFree(ref hBinding);
        }

        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        protected IntPtr GetProcStringHandle(int offset)
        {
            return Marshal.UnsafeAddrOfPinnedArrayElement(MIDL_ProcFormatString, offset);
        }

        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        protected IntPtr GetStubHandle()
        {
            return stub.AddrOfPinnedObject();
        }

        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        protected IntPtr CallNdrClientCall2x86(int offset, params IntPtr[] args)
        {

            GCHandle stackhandle = GCHandle.Alloc(args, GCHandleType.Pinned);
            IntPtr result;
            try
            {
                result = NativeMethods.NdrClientCall2x86(GetStubHandle(), GetProcStringHandle(offset), stackhandle.AddrOfPinnedObject());
            }
            finally
            {
                stackhandle.Free();
            }
            return result;
        }

    }
}
