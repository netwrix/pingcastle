using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Permissions;

namespace PingCastle.RPC
{
    public class RpcFirewallChecker : rpcapi
    {
        
        int maxOpNum;

        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        private RpcFirewallChecker(Guid interfaceId, string pipe, ushort majorVersion, ushort minorVersion, int maxOpNum)
        {
            byte[] MIDL_ProcFormatString;
            byte[] MIDL_TypeFormatString;

            this.maxOpNum = maxOpNum;
            if (IntPtr.Size == 8)
            {
                MIDL_ProcFormatString = new byte[30 * maxOpNum + 1];
                for (byte i = 0; i < maxOpNum; i++)
                {
                    var v = new byte[] { 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, i, 0x00, 0x08, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                    Array.Copy(v, 0, MIDL_ProcFormatString, 30 * i, v.Length);
                }
                MIDL_TypeFormatString = new byte[3];
                InitializeStub(interfaceId, MIDL_ProcFormatString, MIDL_TypeFormatString, "\\pipe\\" + pipe, majorVersion, minorVersion);
            }
            else
            {
                MIDL_ProcFormatString = new byte[28 * maxOpNum + 1];
                for (byte i = 0; i < maxOpNum; i++)
                {
                    var v = new byte[] { 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, i, 0x00, 0x04, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                    Array.Copy(v, 0, MIDL_ProcFormatString, 28 * i, v.Length);
                }
                MIDL_TypeFormatString = new byte[3];
                InitializeStub(interfaceId, MIDL_ProcFormatString, MIDL_TypeFormatString, "\\pipe\\" + pipe, majorVersion, minorVersion);
            }
        }

        [SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        ~RpcFirewallChecker()
        {
            freeStub();
        }

        private int CheckOpNum(int opnum, string server)
        {
            IntPtr result = IntPtr.Zero;
            IntPtr binding = IntPtr.Zero;
            if (opnum >= maxOpNum)
                throw new ApplicationException("opnum above limit");
            try
            {
                var res = BindUsingPipe(server, out binding);
                if (res != 0)
                    return res;

                if (IntPtr.Size == 8)
                {
                    // exception expected : either permission denied or stub mismatch
                    result = NativeMethods.NdrClientCall2x64(GetStubHandle(), GetProcStringHandle(30 * opnum), binding);
                }
                else
                {
                    // exception expected : either permission denied or stub mismatch
                    result = CallNdrClientCall2x86(28 * opnum, binding);
                }
            }
            catch (SEHException)
            {
                Trace.WriteLine("RPC call failed 0x" + Marshal.GetExceptionCode().ToString("x") + " " + Marshal.GetExceptionCode());
                return Marshal.GetExceptionCode();
            }
            finally
            {
                if (binding != IntPtr.Zero)
                    Unbind(IntPtr.Zero, binding);
            }
            return result.ToInt32();
        }

        public static int CheckRPCOpnum(Guid interfaceId, string pipe, ushort majorVersion, ushort minorVersion, int opnum, string server)
        {
            var checker = new RpcFirewallChecker(interfaceId, pipe, majorVersion, minorVersion, opnum + 1);
            return checker.CheckOpNum(opnum, server);
        }

        public static List<string> TestFunctions(string server, Guid interfaceId, string pipe, ushort majorVersion, ushort minorVersion, Dictionary<string, int> functionsToTest)
        {
            List<string> output = new List<string>();
            foreach (var function in functionsToTest)
            {
                var expectedError = CheckRPCOpnum(interfaceId, pipe, majorVersion, minorVersion, function.Value, server);
                if (expectedError == 1783)
                    output.Add(function.Key);
            }

            return output;
        }

    }
}
