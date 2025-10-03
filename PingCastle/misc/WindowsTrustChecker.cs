using System.Reflection;
using System.Runtime.InteropServices;
using System;

namespace PingCastle.misc
{
    using System.IO;

    public static class WindowsTrustChecker
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public class WinTrustFileInfo
        {
            public UInt32 StructSize = (UInt32)Marshal.SizeOf(typeof(WinTrustFileInfo));
            public IntPtr pszFilePath;
            public IntPtr hFile = IntPtr.Zero;
            public IntPtr pgKnownSubject = IntPtr.Zero;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public class WinTrustData
        {
            public UInt32 StructSize = (UInt32)Marshal.SizeOf(typeof(WinTrustData));
            public IntPtr PolicyCallbackData = IntPtr.Zero;
            public IntPtr SIPClientData = IntPtr.Zero;
            public UInt32 UIChoice = 2;
            public UInt32 RevocationChecks = 0;
            public UInt32 UnionChoice = 1;
            public IntPtr FileInfoPtr;
            public UInt32 StateAction = 0;
            public IntPtr StateData = IntPtr.Zero;
            public String URLReference = null;
            public UInt32 ProvFlags = 0x00000010;
            public UInt32 UIContext = 0;
        }

        public class WinTrust
        {
            [DllImport("wintrust.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
            public static extern uint WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID, [MarshalAs(UnmanagedType.LPStruct)] WinTrustData pWVTData);

            public static Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
        }

        public static uint CheckWinTrustFlags(Assembly assembly)
        {
            var path = assembly.Location;
            if (string.IsNullOrEmpty(path))
            {
                System.Diagnostics.Trace.WriteLine("In memory location detected");
                return 0x80070002;
            }
            else if (File.Exists(path))
            {
                return CheckWinTrustFlags(path);
            }
            return 0;
        }

        public static uint CheckWinTrustFlags(string filePath)
        {
            WinTrustFileInfo fileInfo = new WinTrustFileInfo
            {
                pszFilePath = Marshal.StringToCoTaskMemAuto(filePath)
            };

            WinTrustData trustData = new WinTrustData
            {
                FileInfoPtr = Marshal.AllocCoTaskMem(Marshal.SizeOf(typeof(WinTrustFileInfo))),
                RevocationChecks = 0,
            };
            Marshal.StructureToPtr(fileInfo, trustData.FileInfoPtr, false);

            uint result = WinTrust.WinVerifyTrust(IntPtr.Subtract(IntPtr.Zero, 1), WinTrust.WINTRUST_ACTION_GENERIC_VERIFY_V2, trustData);

            Marshal.FreeCoTaskMem(fileInfo.pszFilePath);
            Marshal.FreeCoTaskMem(trustData.FileInfoPtr);

            return result;
        }

    }
}