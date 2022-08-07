using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Permissions;

namespace PingCastle.RPC
{
    public class rprn : rpcapi
    {
        // malware designers:
        // please not reuse this class
        // or if you get inspiration from it, rename at least the class & variables ...
        // AV providers are using hash of variable to setup signatures.

        // AV providers:
        // PingCastle binaries are signed (even debug build)
        // If you setup a signature for this class,
        // please do not report signed binaries by PingCastle

        private static byte[] MIDL_ProcFormatStringx86 = Convert.FromBase64String("AEgAAAAAAAAIADIAAAAAAAgARAEIAQAAAAAAAHAABAAIAABIAAAAAAEAGAAxBAAAAFwIAEAARgYIBQAAAQAAAAsAAAACABABBAAKAAsACAACAAsBDAAeAEgAEAAIAHAAFAAIAABIAAAAAAIACAAyAAAAAAAIAEQBCAEAAAAAAABwAAQACAAASAAAAAADAAgAMgAAAAAACABEAQgBAAAAAAAAcAAEAAgAAEgAAAAABAAIADIAAAAAAAgARAEIAQAAAAAAAHAABAAIAABIAAAAAAUACAAyAAAAAAAIAEQBCAEAAAAAAABwAAQACAAASAAAAAAGAAgAMgAAAAAACABEAQgBAAAAAAAAcAAEAAgAAEgAAAAABwAIADIAAAAAAAgARAEIAQAAAAAAAHAABAAIAABIAAAAAAgACAAyAAAAAAAIAEQBCAEAAAAAAABwAAQACAAASAAAAAAJAAgAMgAAAAAACABEAQgBAAAAAAAAcAAEAAgAAEgAAAAACgAIADIAAAAAAAgARAEIAQAAAAAAAHAABAAIAABIAAAAAAsACAAyAAAAAAAIAEQBCAEAAAAAAABwAAQACAAASAAAAAAMAAgAMgAAAAAACABEAQgBAAAAAAAAcAAEAAgAAEgAAAAADQAIADIAAAAAAAgARAEIAQAAAAAAAHAABAAIAABIAAAAAA4ACAAyAAAAAAAIAEQBCAEAAAAAAABwAAQACAAASAAAAAAPAAgAMgAAAAAACABEAQgBAAAAAAAAcAAEAAgAAEgAAAAAEAAIADIAAAAAAAgARAEIAQAAAAAAAHAABAAIAABIAAAAABEACAAyAAAAAAAIAEQBCAEAAAAAAABwAAQACAAASAAAAAASAAgAMgAAAAAACABEAQgBAAAAAAAAcAAEAAgAAEgAAAAAEwAIADIAAAAAAAgARAEIAQAAAAAAAHAABAAIAABIAAAAABQACAAyAAAAAAAIAEQBCAEAAAAAAABwAAQACAAASAAAAAAVAAgAMgAAAAAACABEAQgBAAAAAAAAcAAEAAgAAEgAAAAAFgAIADIAAAAAAAgARAEIAQAAAAAAAHAABAAIAABIAAAAABcACAAyAAAAAAAIAEQBCAEAAAAAAABwAAQACAAASAAAAAAYAAgAMgAAAAAACABEAQgBAAAAAAAAcAAEAAgAAEgAAAAAGQAIADIAAAAAAAgARAEIAQAAAAAAAHAABAAIAABIAAAAABoACAAyAAAAAAAIAEQBCAEAAAAAAABwAAQACAAASAAAAAAbAAgAMgAAAAAACABEAQgBAAAAAAAAcAAEAAgAAEgAAAAAHAAIADIAAAAAAAgARAEIAQAAAAAAAHAABAAIAABIAAAAAB0ACAAw4AAAAAA4AEAARAIIAQAAAAAAABgBAAA2AHAABAAIAABIAAAAAB4ACAAyAAAAAAAIAEQBCAEAAAAAAABwAAQACAAASAAAAAAfAAgAMgAAAAAACABEAQgBAAAAAAAAcAAEAAgAAEgAAAAAIAAIADIAAAAAAAgARAEIAQAAAAAAAHAABAAIAABIAAAAACEACAAyAAAAAAAIAEQBCAEAAAAAAABwAAQACAAASAAAAAAiAAgAMgAAAAAACABEAQgBAAAAAAAAcAAEAAgAAEgAAAAAIwAIADIAAAAAAAgARAEIAQAAAAAAAHAABAAIAABIAAAAACQACAAyAAAAAAAIAEQBCAEAAAAAAABwAAQACAAASAAAAAAlAAQAMgAAAAAAAABAAAgBAAAAAAAAAEgAAAAAJgAEADIAAAAAAAAAQAAIAQAAAAAAAABIAAAAACcACAAyAAAAAAAIAEQBCAEAAAAAAABwAAQACAAASAAAAAAoAAgAMgAAAAAACABEAQgBAAAAAAAAcAAEAAgAAEgAAAAAKQAIADIAAAAAAAgARAEIAQAAAAAAAHAABAAIAABIAAAAACoACAAyAAAAAAAIAEQBCAEAAAAAAABwAAQACAAASAAAAAArAAQAMgAAAAAAAABAAAgBAAAAAAAAAEgAAAAALAAEADIAAAAAAAAAQAAIAQAAAAAAAABIAAAAAC0ABAAyAAAAAAAAAEAACAEAAAAAAAAASAAAAAAuAAgAMgAAAAAACABEAQgBAAAAAAAAcAAEAAgAAEgAAAAALwAIADIAAAAAAAgARAEIAQAAAAAAAHAABAAIAABIAAAAADAACAAyAAAAAAAIAEQBCAEAAAAAAABwAAQACAAASAAAAAAxAAQAMgAAAAAAAABAAAgBAAAAAAAAAEgAAAAAMgAEADIAAAAAAAAAQAAIAQAAAAAAAABIAAAAADMACAAyAAAAAAAIAEQBCAEAAAAAAABwAAQACAAASAAAAAA0AAgAMgAAAAAACABEAQgBAAAAAAAAcAAEAAgAAEgAAAAANQAIADIAAAAAAAgARAEIAQAAAAAAAHAABAAIAABIAAAAADYABAAyAAAAAAAAAEAACAEAAAAAAAAASAAAAAA3AAQAMgAAAAAAAABAAAgBAAAAAAAAAEgAAAAAOAAIADIAAAAAAAgARAEIAQAAAAAAAHAABAAIAABIAAAAADkABAAyAAAAAAAAAEAACAEAAAAAAAAASAAAAAA6AAgAMgAAAAAACABEAQgBAAAAAAAAcAAEAAgAAEgAAAAAOwAIADIAAAAAAAgARAEIAQAAAAAAAHAABAAIAABIAAAAADwACAAyAAAAAAAIAEQBCAEAAAAAAABwAAQACAAASAAAAAA9AAgAMgAAAAAACABEAQgBAAAAAAAAcAAEAAgAAEgAAAAAPgAIADIAAAAAAAgARAEIAQAAAAAAAHAABAAIAABIAAAAAD8ABAAyAAAAAAAAAEAACAEAAAAAAAAASAAAAABAAAQAMgAAAAAAAABAAAgBAAAAAAAAAEgAAAAAQQAcADBAAAAAADwACABGBwgFAAABAAAACAAAADoASAAEAAgASAAIAAgACwAMAAIASAAQAAgACwAUAD4AcAAYAAgAAA==");

        private static byte[] MIDL_ProcFormatStringx64 = Convert.FromBase64String("AEgAAAAAAAAQADIAAAAAAAgARAEKAQAAAAAAAAAAcAAIAAgAAEgAAAAAAQAwADEIAAAAXAgAQABGBgoFAAABAAAAAAALAAAAAgAQAQgACgALABAAAgALARgAHgBIACAACABwACgACAAASAAAAAACABAAMgAAAAAACABEAQoBAAAAAAAAAABwAAgACAAASAAAAAADABAAMgAAAAAACABEAQoBAAAAAAAAAABwAAgACAAASAAAAAAEABAAMgAAAAAACABEAQoBAAAAAAAAAABwAAgACAAASAAAAAAFABAAMgAAAAAACABEAQoBAAAAAAAAAABwAAgACAAASAAAAAAGABAAMgAAAAAACABEAQoBAAAAAAAAAABwAAgACAAASAAAAAAHABAAMgAAAAAACABEAQoBAAAAAAAAAABwAAgACAAASAAAAAAIABAAMgAAAAAACABEAQoBAAAAAAAAAABwAAgACAAASAAAAAAJABAAMgAAAAAACABEAQoBAAAAAAAAAABwAAgACAAASAAAAAAKABAAMgAAAAAACABEAQoBAAAAAAAAAABwAAgACAAASAAAAAALABAAMgAAAAAACABEAQoBAAAAAAAAAABwAAgACAAASAAAAAAMABAAMgAAAAAACABEAQoBAAAAAAAAAABwAAgACAAASAAAAAANABAAMgAAAAAACABEAQoBAAAAAAAAAABwAAgACAAASAAAAAAOABAAMgAAAAAACABEAQoBAAAAAAAAAABwAAgACAAASAAAAAAPABAAMgAAAAAACABEAQoBAAAAAAAAAABwAAgACAAASAAAAAAQABAAMgAAAAAACABEAQoBAAAAAAAAAABwAAgACAAASAAAAAARABAAMgAAAAAACABEAQoBAAAAAAAAAABwAAgACAAASAAAAAASABAAMgAAAAAACABEAQoBAAAAAAAAAABwAAgACAAASAAAAAATABAAMgAAAAAACABEAQoBAAAAAAAAAABwAAgACAAASAAAAAAUABAAMgAAAAAACABEAQoBAAAAAAAAAABwAAgACAAASAAAAAAVABAAMgAAAAAACABEAQoBAAAAAAAAAABwAAgACAAASAAAAAAWABAAMgAAAAAACABEAQoBAAAAAAAAAABwAAgACAAASAAAAAAXABAAMgAAAAAACABEAQoBAAAAAAAAAABwAAgACAAASAAAAAAYABAAMgAAAAAACABEAQoBAAAAAAAAAABwAAgACAAASAAAAAAZABAAMgAAAAAACABEAQoBAAAAAAAAAABwAAgACAAASAAAAAAaABAAMgAAAAAACABEAQoBAAAAAAAAAABwAAgACAAASAAAAAAbABAAMgAAAAAACABEAQoBAAAAAAAAAABwAAgACAAASAAAAAAcABAAMgAAAAAACABEAQoBAAAAAAAAAABwAAgACAAASAAAAAAdABAAMOAAAAAAOABAAEQCCgEAAAAAAAAAABgBAAAyAHAACAAIAABIAAAAAB4AEAAyAAAAAAAIAEQBCgEAAAAAAAAAAHAACAAIAABIAAAAAB8AEAAyAAAAAAAIAEQBCgEAAAAAAAAAAHAACAAIAABIAAAAACAAEAAyAAAAAAAIAEQBCgEAAAAAAAAAAHAACAAIAABIAAAAACEAEAAyAAAAAAAIAEQBCgEAAAAAAAAAAHAACAAIAABIAAAAACIAEAAyAAAAAAAIAEQBCgEAAAAAAAAAAHAACAAIAABIAAAAACMAEAAyAAAAAAAIAEQBCgEAAAAAAAAAAHAACAAIAABIAAAAACQAEAAyAAAAAAAIAEQBCgEAAAAAAAAAAHAACAAIAABIAAAAACUACAAyAAAAAAAAAEAACgEAAAAAAAAAAABIAAAAACYACAAyAAAAAAAAAEAACgEAAAAAAAAAAABIAAAAACcAEAAyAAAAAAAIAEQBCgEAAAAAAAAAAHAACAAIAABIAAAAACgAEAAyAAAAAAAIAEQBCgEAAAAAAAAAAHAACAAIAABIAAAAACkAEAAyAAAAAAAIAEQBCgEAAAAAAAAAAHAACAAIAABIAAAAACoAEAAyAAAAAAAIAEQBCgEAAAAAAAAAAHAACAAIAABIAAAAACsACAAyAAAAAAAAAEAACgEAAAAAAAAAAABIAAAAACwACAAyAAAAAAAAAEAACgEAAAAAAAAAAABIAAAAAC0ACAAyAAAAAAAAAEAACgEAAAAAAAAAAABIAAAAAC4AEAAyAAAAAAAIAEQBCgEAAAAAAAAAAHAACAAIAABIAAAAAC8AEAAyAAAAAAAIAEQBCgEAAAAAAAAAAHAACAAIAABIAAAAADAAEAAyAAAAAAAIAEQBCgEAAAAAAAAAAHAACAAIAABIAAAAADEACAAyAAAAAAAAAEAACgEAAAAAAAAAAABIAAAAADIACAAyAAAAAAAAAEAACgEAAAAAAAAAAABIAAAAADMAEAAyAAAAAAAIAEQBCgEAAAAAAAAAAHAACAAIAABIAAAAADQAEAAyAAAAAAAIAEQBCgEAAAAAAAAAAHAACAAIAABIAAAAADUAEAAyAAAAAAAIAEQBCgEAAAAAAAAAAHAACAAIAABIAAAAADYACAAyAAAAAAAAAEAACgEAAAAAAAAAAABIAAAAADcACAAyAAAAAAAAAEAACgEAAAAAAAAAAABIAAAAADgAEAAyAAAAAAAIAEQBCgEAAAAAAAAAAHAACAAIAABIAAAAADkACAAyAAAAAAAAAEAACgEAAAAAAAAAAABIAAAAADoAEAAyAAAAAAAIAEQBCgEAAAAAAAAAAHAACAAIAABIAAAAADsAEAAyAAAAAAAIAEQBCgEAAAAAAAAAAHAACAAIAABIAAAAADwAEAAyAAAAAAAIAEQBCgEAAAAAAAAAAHAACAAIAABIAAAAAD0AEAAyAAAAAAAIAEQBCgEAAAAAAAAAAHAACAAIAABIAAAAAD4AEAAyAAAAAAAIAEQBCgEAAAAAAAAAAHAACAAIAABIAAAAAD8ACAAyAAAAAAAAAEAACgEAAAAAAAAAAABIAAAAAEAACAAyAAAAAAAAAEAACgEAAAAAAAAAAABIAAAAAEEAOAAwQAAAAAA8AAgARgcKBQAAAQAAAAAACAAAADYASAAIAAgASAAQAAgACwAYAAIASAAgAAgACwAoADoAcAAwAAgAAA==");


        private static byte[] MIDL_TypeFormatStringx86_clamav2 = Convert.FromBase64String("AAASCCVcEQQCADCgAAARAA4AGwABABkAAAABAAFbFgMIAEtcRlwEAAQAEgDm/1sICFsRBAIAMOEAADBBAAASAEgAGwECABkADAABAAZbFgMUAEtcRlwQABAAEgDm/1sGBggICAhbGwMUABkACAABAEtcSEkUAAAAAQAQABAAEgDC/1tMAMn/WxYDEABLXEZcDAAMABIA0P9bCAgICFsA");

        private static byte[] MIDL_TypeFormatStringx64_clamav2 = Convert.FromBase64String("AAASCCVcEQQCADCgAAARAA4AGwABABkAAAABAAFbGgMQAAAABgAIQDZbEgDm/xEEAgAw4QAAMEEAABIAOAAbAQIAGQAMAAEABlsaAxgAAAAKAAYGCAgINlxbEgDi/yEDAAAZAAgAAQD/////AABMANr/XFsaAxgAAAAIAAgICEA2WxIA2v8A");

        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        public rprn()
        {
            Guid interfaceId = new Guid(magic(8) + "-" + magic(4) + "-ABCD-EF00-0123456789AB");
            if (IntPtr.Size == 8)
            {
                InitializeStub(interfaceId, MIDL_ProcFormatStringx64, MIDL_TypeFormatStringx64_clamav2, "\\" + Reverse("epip") + "\\" + Reverse("ssloops"));
            }
            else
            {
                InitializeStub(interfaceId, MIDL_ProcFormatStringx86, MIDL_TypeFormatStringx86_clamav2, "\\" + Reverse("epip") + "\\" + Reverse("ssloops"));
            }
        }

        [SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        ~rprn()
        {
            freeStub();
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct DEVMODE_CONTAINER
        {
            Int32 cbBuf;
            IntPtr pDevMode;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct RPC_V2_NOTIFY_OPTIONS_TYPE
        {
            UInt16 Type;
            UInt16 Reserved0;
            UInt32 Reserved1;
            UInt32 Reserved2;
            UInt32 Count;
            IntPtr pFields;
        };

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct RPC_V2_NOTIFY_OPTIONS
        {
            UInt32 Version;
            UInt32 Reserved;
            UInt32 Count;
            /* [unique][size_is] */
            RPC_V2_NOTIFY_OPTIONS_TYPE pTypes;
        };

        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        public Int32 RpcOpenPrinter(string pPrinterName, out IntPtr pHandle, string pDatatype, ref DEVMODE_CONTAINER pDevModeContainer, Int32 AccessRequired)
        {
            IntPtr result = IntPtr.Zero;
            IntPtr intptrPrinterName = Marshal.StringToHGlobalUni(pPrinterName);
            IntPtr intptrDatatype = Marshal.StringToHGlobalUni(pDatatype);
            pHandle = IntPtr.Zero;
            try
            {
                if (IntPtr.Size == 8)
                {
                    result = NativeMethods.NdrClientCall2x64(GetStubHandle(), GetProcStringHandle(36), pPrinterName, out pHandle, pDatatype, ref pDevModeContainer, AccessRequired);
                }
                else
                {
                    IntPtr tempValue = IntPtr.Zero;
                    GCHandle handle = GCHandle.Alloc(tempValue, GCHandleType.Pinned);
                    IntPtr tempValuePointer = handle.AddrOfPinnedObject();
                    GCHandle handleDevModeContainer = GCHandle.Alloc(pDevModeContainer, GCHandleType.Pinned);
                    IntPtr tempValueDevModeContainer = handleDevModeContainer.AddrOfPinnedObject();
                    try
                    {
                        result = CallNdrClientCall2x86(34, intptrPrinterName, tempValuePointer, intptrDatatype, tempValueDevModeContainer, new IntPtr(AccessRequired));
                        // each pinvoke work on a copy of the arguments (without an out specifier)
                        // get back the data
                        pHandle = Marshal.ReadIntPtr(tempValuePointer);
                    }
                    finally
                    {
                        handle.Free();
                        handleDevModeContainer.Free();
                    }
                }
            }
            catch (SEHException)
            {
                Trace.WriteLine("RpcOpenPrinter failed 0x" + Marshal.GetExceptionCode().ToString("x"));
                return Marshal.GetExceptionCode();
            }
            finally
            {
                if (intptrPrinterName != IntPtr.Zero)
                    Marshal.FreeHGlobal(intptrPrinterName);
                if (intptrDatatype != IntPtr.Zero)
                    Marshal.FreeHGlobal(intptrDatatype);
            }
            return (int)result.ToInt64();
        }

        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        public Int32 RpcClosePrinter(ref IntPtr ServerHandle)
        {
            IntPtr result = IntPtr.Zero;
            try
            {
                if (IntPtr.Size == 8)
                {
                    result = NativeMethods.NdrClientCall2x64(GetStubHandle(), GetProcStringHandle(1076), ref ServerHandle);
                }
                else
                {
                    IntPtr tempValue = ServerHandle;
                    GCHandle handle = GCHandle.Alloc(tempValue, GCHandleType.Pinned);
                    IntPtr tempValuePointer = handle.AddrOfPinnedObject();
                    try
                    {
                        result = CallNdrClientCall2x86(1018, tempValuePointer);
                        // each pinvoke work on a copy of the arguments (without an out specifier)
                        // get back the data
                        ServerHandle = Marshal.ReadIntPtr(tempValuePointer);
                    }
                    finally
                    {
                        handle.Free();
                    }
                }
            }
            catch (SEHException)
            {
                Trace.WriteLine("RpcClosePrinter failed 0x" + Marshal.GetExceptionCode().ToString("x"));
                return Marshal.GetExceptionCode();
            }
            return (int)result.ToInt64();
        }

        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        public Int32 RpcRemoteFindFirstPrinterChangeNotificationEx(
            /* [in] */ IntPtr hPrinter,
            /* [in] */ UInt32 fdwFlags,
            /* [in] */ UInt32 fdwOptions,
            /* [unique][string][in] */ string pszLocalMachine,
            /* [in] */ UInt32 dwPrinterLocal)
        {
            IntPtr result = IntPtr.Zero;
            IntPtr intptrLocalMachine = Marshal.StringToHGlobalUni(pszLocalMachine);
            try
            {
                if (IntPtr.Size == 8)
                {
                    result = NativeMethods.NdrClientCall2x64(GetStubHandle(), GetProcStringHandle(2308), hPrinter, fdwFlags, fdwOptions, pszLocalMachine, dwPrinterLocal, IntPtr.Zero);
                }
                else
                {
                    try
                    {
                        result = CallNdrClientCall2x86(2178, hPrinter, new IntPtr(fdwFlags), new IntPtr(fdwOptions), intptrLocalMachine, new IntPtr(dwPrinterLocal), IntPtr.Zero);
                        // each pinvoke work on a copy of the arguments (without an out specifier)
                        // get back the data
                    }
                    finally
                    {
                    }
                }
            }
            catch (SEHException)
            {
                Trace.WriteLine("RpcRemoteFindFirstPrinterChangeNotificationEx failed 0x" + Marshal.GetExceptionCode().ToString("x"));
                return Marshal.GetExceptionCode();
            }
            finally
            {
                if (intptrLocalMachine != IntPtr.Zero)
                    Marshal.FreeHGlobal(intptrLocalMachine);
            }
            return (int)result.ToInt64();
        }
    }
}
