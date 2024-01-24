using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using System.Text;
using System.Threading.Tasks;

namespace PingCastle.RPC
{
    public class RpcFirewallChecker : rpcapi
    {
        private static byte[] MIDL_ProcFormatStringx86;

        private static byte[] MIDL_ProcFormatStringx64;

        private static byte[] MIDL_TypeFormatStringx64;

        private static byte[] MIDL_TypeFormatStringx86;

        int maxOpNum;

        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        private RpcFirewallChecker(Guid interfaceId, string pipe, ushort majorVersion, ushort minorVersion, int maxOpNum)
        {
            this.maxOpNum = maxOpNum;
            if (IntPtr.Size == 8)
            {
                MIDL_ProcFormatStringx64 = new byte[30 * maxOpNum + 1];
                for (byte i = 0; i < maxOpNum; i++)
                {
                    var v = new byte[] { 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, i, 0x00, 0x08, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                    Array.Copy(v, 0, MIDL_ProcFormatStringx64, 30 * i, v.Length);
                }
                MIDL_TypeFormatStringx64 = new byte[3];
                InitializeStub(interfaceId, MIDL_ProcFormatStringx64, MIDL_TypeFormatStringx64, "\\pipe\\" + pipe, majorVersion, minorVersion);
            }
            else
            {
                MIDL_ProcFormatStringx86 = new byte[28 * maxOpNum + 1];
                for (byte i = 0; i < maxOpNum; i++)
                {
                    var v = new byte[] { 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, i, 0x00, 0x04, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                    Array.Copy(v, 0, MIDL_ProcFormatStringx86, 28 * i, v.Length);
                }
                MIDL_TypeFormatStringx86 = new byte[3];
                InitializeStub(interfaceId, MIDL_ProcFormatStringx86, MIDL_TypeFormatStringx86, "\\pipe\\" + pipe, majorVersion, minorVersion);
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

        public static bool CheckElfrOpenBELW(string server)
        {
            var expectedError = CheckRPCOpnum(Guid.Parse("82273fdc-e32a-18c3-3f78-827929dc23ea"), "eventlog", 0, 0, 17, server);
            if (expectedError == 1783)
                return true;
            return false;
        }

        public static bool CheckEfsRpcAddUsersToFile(string server)
        {
            var expectedError = CheckRPCOpnum(Guid.Parse("df1941c5-fe89-4e79-bf10-463657acf44d"), "netlogon", 1, 0, 9, server);
            if (expectedError == 1783)
                return true;
            return false;
        }

        public static bool CheckRpcRemoteFindFirstPrinterChangeNotification(string server)
        {
            var expectedError = CheckRPCOpnum(Guid.Parse("12345678-1234-abcd-ef00-0123456789ab"), "spoolss", 1, 0, 9, server);
            if (expectedError == 1783)
                return true;
            return false;
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
