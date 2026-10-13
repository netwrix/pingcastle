using System.Runtime.InteropServices;

namespace Netwrix.AuthenticodeVerification.Interop;

/// <summary>
/// Managed layout of Windows
/// <see href="https://learn.microsoft.com/windows/win32/api/wincrypt/ns-wincrypt-cert_strong_sign_para"><c>CERT_STRONG_SIGN_PARA</c></see>.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = NativeLayout.InteropStructurePack)]
internal struct CertStrongSignParameters
{
    public uint Size;
    public uint InformationChoice;
    public IntPtr Information;
}

/// <summary>
/// Managed layout of Windows
/// <see href="https://learn.microsoft.com/windows/win32/api/wintrust/ns-wintrust-wintrust_signature_settings"><c>WINTRUST_SIGNATURE_SETTINGS</c></see>.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = NativeLayout.InteropStructurePack)]
internal struct WinTrustSignatureSettings
{
    public uint Size;
    public uint Index;
    public uint Flags;
    public uint SecondarySignatureCount;
    public uint VerifiedSignatureIndex;
    public IntPtr CryptoPolicy;
}

/// <summary>
/// Managed layout of Windows
/// <see href="https://learn.microsoft.com/windows/win32/api/wintrust/ns-wintrust-wintrust_file_info"><c>WINTRUST_FILE_INFO</c></see>.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = NativeLayout.InteropStructurePack)]
internal struct WinTrustFileInfo
{
    public uint Size;
    public IntPtr FilePath;
    public IntPtr FileHandle;
    public IntPtr KnownSubject;
}

/// <summary>
/// Managed layout of Windows
/// <see href="https://learn.microsoft.com/windows/win32/api/wintrust/ns-wintrust-wintrust_data"><c>WINTRUST_DATA</c></see>.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = NativeLayout.InteropStructurePack)]
internal struct WinTrustData
{
    public uint Size;
    public IntPtr PolicyCallbackData;
    public IntPtr SipClientData;
    public uint UiChoice;
    public uint RevocationChecks;
    public uint UnionChoice;
    public IntPtr FileInfo;
    public uint StateAction;
    public IntPtr StateData;
    public IntPtr UrlReference;
    public uint ProviderFlags;
    public uint UiContext;
    public IntPtr SignatureSettings;
}

/// <summary>
/// Managed layout of Windows
/// <see href="https://learn.microsoft.com/windows/win32/api/minwinbase/ns-minwinbase-filetime"><c>FILETIME</c></see>.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = NativeLayout.InteropStructurePack)]
internal struct NativeFileTime
{
    public uint LowDateTime;
    public uint HighDateTime;

    public bool IsZero => LowDateTime == 0 && HighDateTime == 0;
}

/// <summary>
/// Managed layout of Windows
/// <see href="https://learn.microsoft.com/windows/win32/api/wintrust/ns-wintrust-crypt_provider_data"><c>CRYPT_PROVIDER_DATA</c></see>.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = NativeLayout.InteropStructurePack)]
internal struct CryptProviderData
{
    public uint Size;
    public IntPtr WinTrustData;
    public int OpenedFile;
    public IntPtr ParentWindow;
    public IntPtr ActionId;
    public IntPtr CryptographicProvider;
    public uint Error;
    public uint RegistrySecuritySettings;
    public uint RegistryPolicySettings;
    public IntPtr ProviderFunctions;
    public uint TrustStepErrorCount;
    public IntPtr TrustStepErrors;
    public uint StoreCount;
    public IntPtr Stores;
    public uint Encoding;
    public IntPtr Message;
    public uint SignerCount;
    public IntPtr Signers;
    public uint PrivateDataCount;
    public IntPtr PrivateData;
    public uint SubjectChoice;
    public IntPtr SubjectData;
    public IntPtr UsageOid;
    public int RecallWithState;
    public NativeFileTime SystemTime;
    public IntPtr CtlSignerUsageOid;
    public uint ProviderFlags;
    public uint FinalError;
    public IntPtr RequestUsage;
    public uint TrustPublicationSettings;
    public uint UiStateFlags;
    public IntPtr SignatureState;
    public IntPtr SignatureSettings;
}

/// <summary>
/// Managed layout of Windows
/// <see href="https://learn.microsoft.com/windows/win32/api/wintrust/ns-wintrust-crypt_provider_sgnr"><c>CRYPT_PROVIDER_SGNR</c></see>.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = NativeLayout.InteropStructurePack)]
internal struct CryptProviderSigner
{
    public uint Size;
    public NativeFileTime VerifyAsOf;
    public uint CertificateChainCount;
    public IntPtr CertificateChain;
    public uint SignerType;
    public IntPtr SignerInfo;
    public uint Error;
    public uint CounterSignerCount;
    public IntPtr CounterSigners;
    public IntPtr ChainContext;
}

/// <summary>
/// Managed layout of Windows
/// <see href="https://learn.microsoft.com/windows/win32/api/wintrust/ns-wintrust-crypt_provider_cert"><c>CRYPT_PROVIDER_CERT</c></see>.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = NativeLayout.InteropStructurePack)]
internal struct CryptProviderCertificate
{
    public uint Size;
    public IntPtr Certificate;
    public int Commercial;
    public int TrustedRoot;
    public int SelfSigned;
    public int TestCertificate;
    public uint RevokedReason;
    public uint Confidence;
    public uint Error;
    public IntPtr TrustListContext;
    public int TrustListSignerCertificate;
    public IntPtr CtlContext;
    public uint CtlError;
    public int IsCyclic;
    public IntPtr ChainElement;
}

/// <summary>
/// Managed layout of Windows
/// <see href="https://learn.microsoft.com/windows/win32/api/wincrypt/ns-wincrypt-cert_context"><c>CERT_CONTEXT</c></see>.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = NativeLayout.InteropStructurePack)]
internal struct CertificateContext
{
    public uint EncodingType;
    public IntPtr EncodedCertificate;
    public uint EncodedCertificateSize;
    public IntPtr CertificateInfo;
    public IntPtr CertificateStore;
}

/// <summary>
/// Managed layout of Windows
/// <see href="https://learn.microsoft.com/windows/win32/api/wincrypt/ns-wincrypt-cert_trust_status"><c>CERT_TRUST_STATUS</c></see>.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = NativeLayout.InteropStructurePack)]
internal struct CertificateTrustStatus
{
    public uint ErrorStatus;
    public uint InformationStatus;
}

/// <summary>
/// Managed layout of Windows
/// <see href="https://learn.microsoft.com/windows/win32/api/wincrypt/ns-wincrypt-cert_chain_context"><c>CERT_CHAIN_CONTEXT</c></see>.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = NativeLayout.InteropStructurePack)]
internal struct CertificateChainContext
{
    public uint Size;
    public CertificateTrustStatus TrustStatus;
    public uint ChainCount;
    public IntPtr Chains;
    public uint LowerQualityChainCount;
    public IntPtr LowerQualityChains;
    public int HasRevocationFreshnessTime;
    public uint RevocationFreshnessTime;
    public uint CreateFlags;
    public Guid ChainId;
}

/// <summary>
/// Managed layout of Windows
/// <see href="https://learn.microsoft.com/windows/win32/api/wincrypt/ns-wincrypt-cert_simple_chain"><c>CERT_SIMPLE_CHAIN</c></see>.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = NativeLayout.InteropStructurePack)]
internal struct CertificateSimpleChain
{
    public uint Size;
    public CertificateTrustStatus TrustStatus;
    public uint ElementCount;
    public IntPtr Elements;
    public IntPtr TrustListInfo;
    public int HasRevocationFreshnessTime;
    public uint RevocationFreshnessTime;
}

/// <summary>
/// Managed layout of Windows
/// <see href="https://learn.microsoft.com/windows/win32/api/wincrypt/ns-wincrypt-cert_chain_element"><c>CERT_CHAIN_ELEMENT</c></see>.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = NativeLayout.InteropStructurePack)]
internal struct CertificateChainElement
{
    public uint Size;
    public IntPtr Certificate;
    public CertificateTrustStatus TrustStatus;
    public IntPtr RevocationInfo;
    public IntPtr IssuanceUsage;
    public IntPtr ApplicationUsage;
    public IntPtr ExtendedErrorInfo;
}

internal static class NativeLayout
{
    /// <summary>
    /// The explicit packing used by the managed projections of the WinTrust and CryptoAPI structures.
    /// See <see href="https://learn.microsoft.com/dotnet/api/system.runtime.interopservices.structlayoutattribute.pack"><c>StructLayoutAttribute.Pack</c></see>.
    /// </summary>
    internal const int InteropStructurePack = 8;

    /// <summary>
    /// Verifies that the managed projections have the expected x86 or x64 byte size before any
    /// native call uses them.  The expected sizes are derived from the linked Windows declarations
    /// on each managed structure above.
    /// </summary>
    public static void Validate()
    {
        bool is64Bit = Environment.Is64BitProcess;
        RequireSize<CertStrongSignParameters>(is64Bit, expected32BitSize: 12, expected64BitSize: 16);
        RequireSize<WinTrustSignatureSettings>(is64Bit, expected32BitSize: 24, expected64BitSize: 32);
        RequireSize<WinTrustFileInfo>(is64Bit, expected32BitSize: 16, expected64BitSize: 32);
        RequireSize<WinTrustData>(is64Bit, expected32BitSize: 52, expected64BitSize: 88);
        RequireSize<CryptProviderData>(is64Bit, expected32BitSize: 136, expected64BitSize: 240);
        RequireSize<CryptProviderSigner>(is64Bit, expected32BitSize: 44, expected64BitSize: 64);
        RequireSize<CryptProviderCertificate>(is64Bit, expected32BitSize: 60, expected64BitSize: 88);
        RequireSize<CertificateContext>(is64Bit, expected32BitSize: 20, expected64BitSize: 40);
        RequireSize<CertificateChainContext>(is64Bit, expected32BitSize: 56, expected64BitSize: 72);
        RequireSize<CertificateSimpleChain>(is64Bit, expected32BitSize: 32, expected64BitSize: 40);
        RequireSize<CertificateChainElement>(is64Bit, expected32BitSize: 32, expected64BitSize: 56);
    }

    private static void RequireSize<T>(
        bool is64Bit,
        int expected32BitSize,
        int expected64BitSize)
        where T : struct
    {
        int expectedSize = is64Bit ? expected64BitSize : expected32BitSize;
        int actualSize = Marshal.SizeOf(typeof(T));
        if (actualSize != expectedSize)
        {
            throw new PlatformNotSupportedException(
                $"Native structure {typeof(T).Name} has size {actualSize}; expected {expectedSize}.");
        }
    }
}
