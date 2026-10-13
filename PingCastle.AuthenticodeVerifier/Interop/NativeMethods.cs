using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Netwrix.AuthenticodeVerification.Interop;

internal static class NativeMethods
{
    /// <summary>
    /// Windows <c>FILE_NAME_NORMALIZED</c>, requesting the normalized final path for an open handle.
    /// See <see href="https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew"><c>GetFinalPathNameByHandleW</c></see>.
    /// </summary>
    internal const uint FileNameNormalized = 0x0;

    /// <summary>
    /// Windows <c>VOLUME_NAME_DOS</c>, requesting a final path using DOS drive-letter syntax.
    /// See <see href="https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew"><c>GetFinalPathNameByHandleW</c></see>.
    /// </summary>
    internal const uint VolumeNameDos = 0x0;

    /// <summary>
    /// Windows <c>WINTRUST_ACTION_GENERIC_VERIFY_V2</c>, selecting the Authenticode policy provider.
    /// See <see href="https://learn.microsoft.com/windows/win32/api/wintrust/nf-wintrust-winverifytrust"><c>WinVerifyTrust</c></see>.
    /// </summary>
    internal static readonly Guid WinTrustActionGenericVerifyV2 =
        new("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern uint GetFinalPathNameByHandle(
        SafeFileHandle file,
        StringBuilder filePath,
        uint filePathLength,
        uint flags);

    [DllImport("wintrust.dll", ExactSpelling = true, PreserveSig = true)]
    internal static extern int WinVerifyTrust(
        IntPtr windowHandle,
        ref Guid actionId,
        IntPtr trustData);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    internal static extern IntPtr WTHelperProvDataFromStateData(IntPtr stateData);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    internal static extern IntPtr WTHelperGetProvSignerFromChain(
        IntPtr providerData,
        uint signerIndex,
        int counterSigner,
        uint counterSignerIndex);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    internal static extern IntPtr WTHelperGetProvCertFromChain(
        IntPtr signer,
        uint certificateIndex);
}
