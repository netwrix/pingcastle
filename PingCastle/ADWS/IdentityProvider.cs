namespace PingCastle.ADWS;

using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Principal;
using PingCastleCommon.Utility;

internal class IdentityProvider : IIdentityProvider
{
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LogonUser(string lpszUsername, string lpszDomain, string lpszPassword, int dwLogonType, int dwLogonProvider, ref IntPtr phToken);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    const int LOGON32_LOGON_INTERACTIVE = 2;
    const int LOGON32_LOGON_NEW_CREDENTIALS = 9;
    const int LOGON32_PROVIDER_DEFAULT = 0;

    private readonly IWindowsNativeMethods _nativeMethods;

    public IdentityProvider(IWindowsNativeMethods nativeMethods)
    {
        _nativeMethods = nativeMethods;
    }


    public WindowsIdentity GetWindowsIdentityForUser(NetworkCredential credential, string remoteserver)
    {
        IntPtr token = IntPtr.Zero;
        var szDomain = credential.Domain;
        if (string.IsNullOrEmpty(szDomain))
        {
            if (!credential.UserName.Contains("@"))
            {
                szDomain = remoteserver;
            }
        }
        Trace.WriteLine("Preparing to login with login = " + credential.UserName.SanitizeForLog() + " domain = " + szDomain.SanitizeForLog() + " remoteserver = " + remoteserver.SanitizeForLog());

        // Try INTERACTIVE logon first for Kerberos support (same-domain scenarios)
        // Fall back to NEW_CREDENTIALS for cross-domain/standalone scenarios
        bool isSuccess = LogonUser(credential.UserName, szDomain, credential.Password,
            LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, ref token);
        if (!isSuccess)
        {
            var interactiveError = Marshal.GetLastWin32Error();
            Trace.WriteLine("Interactive logon failed (Win32 error " + interactiveError + "), falling back to NewCredentials");
            isSuccess = LogonUser(credential.UserName, szDomain, credential.Password,
                LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, ref token);
            if (!isSuccess)
            {
                throw new Win32Exception();
            }
        }

        var output = new WindowsIdentity(token);
        CloseHandle(token);
        return output;
    }

    public string ConvertSIDToName(WindowsIdentity identity, string sidstring, string server, out string referencedDomain)
    {
        if (identity != null)
        {
            string tempDomain = null;
            string result = null;
            WindowsIdentity.RunImpersonated(identity.AccessToken, () =>
            {
                result = _nativeMethods.ConvertSIDToName(sidstring, server, out tempDomain);
            });
            referencedDomain = tempDomain;
            return result;
        }
        return _nativeMethods.ConvertSIDToName(sidstring, server, out referencedDomain);
    }
}
