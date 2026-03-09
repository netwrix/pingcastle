using System.Reflection;
using System.Runtime.InteropServices;
using System;

namespace PingCastle.misc
{
    using System.IO;

    public static class WindowsTrustChecker
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WinTrustFileInfo
        {
            public UInt32 cbStruct;
            public IntPtr pszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WinTrustData
        {
            public UInt32 cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public UInt32 dwUIChoice;
            public UInt32 fdwRevocationChecks;
            public UInt32 dwUnionChoice;
            public IntPtr pFileInfo;
            public UInt32 dwStateAction;
            public IntPtr pwState;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwszURLReference;
            public UInt32 dwProvFlags;
            public UInt32 dwUIContext;
        }

        private static class WinTrust
        {
            [DllImport("wintrust.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
            public static extern uint WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID, IntPtr pWVTData);

            public static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
        }

        public static uint CheckWinTrustFlags(Assembly assembly)
        {
            var path = assembly.Location;

            // Try to get entry assembly if current assembly location is empty
            if (string.IsNullOrEmpty(path))
            {
                var entryAssembly = Assembly.GetEntryAssembly();
                if (entryAssembly != null)
                {
                    path = entryAssembly.Location;
                }
            }

            // Fall back to current process executable if still empty
            if (string.IsNullOrEmpty(path))
            {
                try
                {
                    path = System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName;
                }
                catch
                {
                    // Silently continue if unable to get process main module
                }
            }

            if (string.IsNullOrEmpty(path))
            {
                return 0x80070002;
            }

            if (File.Exists(path))
            {
                return CheckWinTrustFlags(path);
            }

            return 0;
        }

        public static uint CheckWinTrustFlags(string filePath)
        {
            if (filePath.EndsWith(".dll"))
            {
                filePath = filePath.Substring(0, filePath.Length - 4) + ".exe";
            }

            IntPtr filePathPtr = Marshal.StringToCoTaskMemUni(filePath);

            try
            {
                WinTrustFileInfo fileInfo = new WinTrustFileInfo
                {
                    cbStruct = (uint)Marshal.SizeOf(typeof(WinTrustFileInfo)),
                    pszFilePath = filePathPtr,
                    hFile = IntPtr.Zero,
                    pgKnownSubject = IntPtr.Zero
                };

                IntPtr fileInfoPtr = Marshal.AllocCoTaskMem(Marshal.SizeOf(typeof(WinTrustFileInfo)));
                try
                {
                    Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);

                    WinTrustData trustData = new WinTrustData
                    {
                        cbStruct = (uint)Marshal.SizeOf(typeof(WinTrustData)),
                        pPolicyCallbackData = IntPtr.Zero,
                        pSIPClientData = IntPtr.Zero,
                        dwUIChoice = 2,
                        fdwRevocationChecks = 0,
                        dwUnionChoice = 1,
                        pFileInfo = fileInfoPtr,
                        dwStateAction = 0,
                        pwState = IntPtr.Zero,
                        pwszURLReference = null,
                        dwProvFlags = 0x00000010,
                        dwUIContext = 0
                    };

                    IntPtr trustDataPtr = Marshal.AllocCoTaskMem(Marshal.SizeOf(typeof(WinTrustData)));
                    try
                    {
                        Marshal.StructureToPtr(trustData, trustDataPtr, false);
                        var checkWinTrustFlags = WinTrust.WinVerifyTrust(IntPtr.Subtract(IntPtr.Zero, 1), WinTrust.WINTRUST_ACTION_GENERIC_VERIFY_V2, trustDataPtr);
                        return checkWinTrustFlags;
                    }
                    finally
                    {
                        Marshal.DestroyStructure(trustDataPtr, typeof(WinTrustData));
                        Marshal.FreeCoTaskMem(trustDataPtr);
                    }
                }
                finally
                {
                    Marshal.DestroyStructure(fileInfoPtr, typeof(WinTrustFileInfo));
                    Marshal.FreeCoTaskMem(fileInfoPtr);
                }
            }
            finally
            {
                Marshal.FreeCoTaskMem(filePathPtr);
            }
        }
    }
}