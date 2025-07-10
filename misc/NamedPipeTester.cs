using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace PingCastle.misc
{
    public class NamedPipeTester
    {
        [DllImport("kernel32.dll", EntryPoint = "CreateFile", SetLastError = true)]
        private static extern IntPtr CreateFile(String lpFileName,
             UInt32 dwDesiredAccess, UInt32 dwShareMode,
             IntPtr lpSecurityAttributes, UInt32 dwCreationDisposition,
             UInt32 dwFlagsAndAttributes,
             IntPtr hTemplateFile);

        private const UInt32 GENERIC_READ = 0x80000000;
        private const UInt32 GENERIC_WRITE = 0x40000000;
        private const UInt32 OPEN_EXISTING = 3;

        public const string WebClientPipeName = "DAV RPC SERVICE";

        static public bool IsRemotePipeAccessible(string server, string pipe, string logPrefix)
        {
            Trace.WriteLine(logPrefix + "Testing " + server + " for " + pipe);
            string path = @"\\" + server + @"\pipe\" + pipe;
            IntPtr p = CreateFile(path, GENERIC_READ + GENERIC_WRITE, 0, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
            if (p.ToInt32() == -1)
            {
                var error = Marshal.GetLastWin32Error();
                Trace.WriteLine(logPrefix + "No handle " + error);
                return false;
            }
            Trace.WriteLine(logPrefix + "Handle acquired");
            var t = new Microsoft.Win32.SafeHandles.SafeFileHandle(p, true);
            t.Close();
            return true;
        }
    }
}
