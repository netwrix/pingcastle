using System;
using System.Diagnostics;
using System.Runtime.InteropServices;


namespace PingCastle.misc
{
    class RestrictedToken
    {

        private static uint STANDARD_RIGHTS_READ = 0x00020000;
        private static uint TOKEN_QUERY = 0x0008;
        private static uint TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, UInt32 DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, ref TOKEN_ELEVATION_TYPE elevationType, uint TokenInformationLength, out uint ReturnLength);

        [DllImport("Kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        //https://docs.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class
        public enum TOKEN_INFORMATION_CLASS
        {
            TokenUser = 1,
            TokenGroups,
            TokenPrivileges,
            TokenOwner,
            TokenPrimaryGroup,
            TokenDefaultDacl,
            TokenSource,
            TokenType,
            TokenImpersonationLevel,
            TokenStatistics,
            TokenRestrictedSids,
            TokenSessionId,
            TokenGroupsAndPrivileges,
            TokenSessionReference,
            TokenSandBoxInert,
            TokenAuditPolicy,
            TokenOrigin,
            TokenElevationType,
            TokenLinkedToken,
            TokenElevation,
            TokenHasRestrictions,
            TokenAccessInformation,
            TokenVirtualizationAllowed,
            TokenVirtualizationEnabled,
            TokenIntegrityLevel,
            TokenUIAccess,
            TokenMandatoryPolicy,
            TokenLogonSid,
            MaxTokenInfoClass
        }

        //https://docs.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_elevation_type
        public enum TOKEN_ELEVATION_TYPE
        {
            TokenElevationTypeDefault = 1,
            TokenElevationTypeFull,
            TokenElevationTypeLimited
        }

        public static bool IsUsingRestrictedToken
        {
            get
            {
                IntPtr tokenHandle;
                if (!OpenProcessToken(Process.GetCurrentProcess().Handle, TOKEN_READ, out tokenHandle))
                {
                    Trace.WriteLine("Could not get process token.  Win32 Error Code: " + Marshal.GetLastWin32Error());
                    return false;
                }
                try
                {
                    TOKEN_ELEVATION_TYPE elevationResult = TOKEN_ELEVATION_TYPE.TokenElevationTypeDefault;

                    uint returnedSize;
                    bool success = GetTokenInformation(tokenHandle, TOKEN_INFORMATION_CLASS.TokenElevationType, ref elevationResult, (uint)Marshal.SizeOf(typeof(int)), out returnedSize);
                    if (success)
                    {
                        Trace.WriteLine("Elevation type is: " + elevationResult);
                        return elevationResult == TOKEN_ELEVATION_TYPE.TokenElevationTypeLimited;
                    }
                    else
                    {
                        Trace.WriteLine("Unable to determine the current elevation.  Win32 Error Code: " + Marshal.GetLastWin32Error());
                        return false;
                    }
                }
                finally
                {
                    CloseHandle(tokenHandle);
                }
            }
        }
    }
}