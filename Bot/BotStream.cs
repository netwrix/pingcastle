using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;

namespace PingCastle.Bot
{
    internal class BotStream
    {
        [DllImport("kernel32.dll", EntryPoint = "CreateFile", SetLastError = true)]
        private static extern IntPtr CreateFile(string lpFileName,
                                                uint dwDesiredAccess,
                                                uint dwShareMode,
                                                IntPtr lpSecurityAttributes,
                                                uint dwCreationDisposition,
                                                uint dwFlagsAndAttributes,
                                                IntPtr hTemplateFile);

        private const uint GENERIC_READ = 0x80000000;
        private const uint GENERIC_WRITE = 0x40000000;
        private const uint OPEN_EXISTING = 3;

        public static FileStream OpenPipeStream(string pipeName)
        {
            Console.WriteLine("Opening pipe :" + pipeName);
            IntPtr p = CreateFile(@"\\.\pipe\" + pipeName, GENERIC_READ + GENERIC_WRITE, 0, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
            if (p.ToInt32() == -1)
            {
                throw new Win32Exception();
            }
            return new FileStream(new Microsoft.Win32.SafeHandles.SafeFileHandle(p, true), FileAccess.ReadWrite);
        }
    }
}