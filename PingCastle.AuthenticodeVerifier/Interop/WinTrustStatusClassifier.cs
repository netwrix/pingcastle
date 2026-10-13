using System.Runtime.InteropServices;

namespace Netwrix.AuthenticodeVerification.Interop;

internal static class WinTrustStatusClassifier
{
    /// <summary>
    /// The first Windows certificate-and-trust failure value included in the reviewed validation range.
    /// See <see href="https://learn.microsoft.com/windows/win32/seccrypto/certificate-and-trust-return-values">Certificate and Trust Return Values</see>.
    /// </summary>
    private const uint CertificateAndTrustStatusRangeStart = 0x800B0100;

    /// <summary>
    /// The last Windows certificate-and-trust failure value included in the reviewed validation range.
    /// See <see href="https://learn.microsoft.com/windows/win32/seccrypto/certificate-and-trust-return-values">Certificate and Trust Return Values</see>.
    /// </summary>
    private const uint CertificateAndTrustStatusRangeEnd = 0x800B0114;

    /// <summary>
    /// Windows <c>CRYPT_E_ASN1_ERROR</c>, the start of the ASN.1 encode/decode failure range.
    /// See <see href="https://learn.microsoft.com/windows/win32/seccrypto/asn-1-encoding-decoding-return-values">ASN.1 Encoding/Decoding Return Values</see>.
    /// </summary>
    private const uint Asn1StatusRangeStart = 0x80093100;

    /// <summary>
    /// Windows <c>CRYPT_E_ASN1_NOEOD</c>, the last ASN.1 encode/decode failure value accepted by this classifier.
    /// See <see href="https://learn.microsoft.com/windows/win32/seccrypto/asn-1-encoding-decoding-return-values">ASN.1 Encoding/Decoding Return Values</see>.
    /// </summary>
    private const uint Asn1StatusRangeEnd = 0x80093202;

    /// <summary>
    /// Windows <c>CRYPT_E_NO_REVOCATION_CHECK</c>, meaning revocation could not be checked.
    /// See <see href="https://learn.microsoft.com/windows/win32/seccrypto/certificate-and-trust-return-values">Certificate and Trust Return Values</see>.
    /// </summary>
    private const uint CryptENoRevocationCheck = 0x80092012;

    /// <summary>
    /// Windows <c>CRYPT_E_REVOCATION_OFFLINE</c>, meaning the revocation server was unavailable.
    /// See <see href="https://learn.microsoft.com/windows/win32/seccrypto/certificate-and-trust-return-values">Certificate and Trust Return Values</see>.
    /// </summary>
    private const uint CryptERevocationOffline = 0x80092013;

    /// <summary>
    /// Windows <c>CERT_E_REVOCATION_FAILURE</c>, meaning the revocation process could not continue.
    /// See <see href="https://learn.microsoft.com/windows/win32/api/wincrypt/ns-wincrypt-cert_chain_policy_status"><c>CERT_CHAIN_POLICY_STATUS</c></see>.
    /// </summary>
    private const uint CertERevocationFailure = 0x800B010E;

    /// <summary>
    /// Windows <c>E_OUTOFMEMORY</c>, the HRESULT form of an allocation failure.
    /// See <see href="https://learn.microsoft.com/windows/win32/seccrypto/common-hresult-values">Common HRESULT Values</see>.
    /// </summary>
    private const uint EOutOfMemory = 0x8007000E;

    /// <summary>
    /// Windows <c>ERROR_NOT_ENOUGH_MEMORY</c>, the Win32 form of insufficient-memory failure.
    /// See <see href="https://learn.microsoft.com/windows/win32/debug/system-error-codes--0-499-">System Error Codes</see>.
    /// </summary>
    private const uint ErrorNotEnoughMemory = 0x00000008;

    /// <summary>
    /// Windows <c>ERROR_OUTOFMEMORY</c>, the Win32 form of an allocation failure.
    /// See <see href="https://learn.microsoft.com/windows/win32/debug/system-error-codes--0-499-">System Error Codes</see>.
    /// </summary>
    private const uint ErrorOutOfMemory = 0x0000000E;

    /// <summary>
    /// Windows <c>E_INVALIDARG</c>, the HRESULT form of an invalid-argument failure.
    /// See <see href="https://learn.microsoft.com/windows/win32/seccrypto/common-hresult-values">Common HRESULT Values</see>.
    /// </summary>
    private const uint EInvalidArgument = 0x80070057;

    /// <summary>
    /// Windows <c>ERROR_INVALID_PARAMETER</c>, the Win32 form of an invalid-argument failure.
    /// See <see href="https://learn.microsoft.com/windows/win32/debug/system-error-codes--0-499-">System Error Codes</see>.
    /// </summary>
    private const uint ErrorInvalidParameter = 0x00000057;

    /// <summary>
    /// Explicit Windows cryptographic and trust statuses that mean validation completed with rejection.
    /// Each value is labelled with its Windows symbolic name; definitions are in
    /// <see href="https://learn.microsoft.com/windows/win32/seccrypto/certificate-and-trust-return-values">Certificate and Trust Return Values</see>.
    /// </summary>
    private static readonly HashSet<int> ValidationStatuses = new()
    {
        Status(ValidationStatus.NteBadSignature),
        Status(ValidationStatus.NteBadAlgorithmId),
        Status(ValidationStatus.CryptEHashValue),
        Status(ValidationStatus.CryptEBadEncode),
        Status(ValidationStatus.CryptEBadMessage),
        Status(ValidationStatus.CryptENoSigner),
        Status(ValidationStatus.CryptERevoked),
        Status(CryptENoRevocationCheck), // CRYPT_E_NO_REVOCATION_CHECK
        Status(CryptERevocationOffline), // CRYPT_E_REVOCATION_OFFLINE
        Status(ValidationStatus.CryptESecuritySettings),
        Status(ValidationStatus.TrustENoSignerCertificate),
        Status(ValidationStatus.TrustECounterSigner),
        Status(ValidationStatus.TrustECertificateSignature),
        Status(ValidationStatus.TrustETimeStamp),
        Status(ValidationStatus.TrustEBadDigest),
        Status(ValidationStatus.TrustEBasicConstraints),
        Status(ValidationStatus.TrustEFinancialCriteria),
        Status(ValidationStatus.TrustEProviderUnknown),
        Status(ValidationStatus.TrustEActionUnknown),
        Status(ValidationStatus.TrustESubjectFormUnknown),
        Status(ValidationStatus.TrustESubjectNotTrusted),
        Status(ValidationStatus.DigitalSignatureEEncode),
        Status(ValidationStatus.DigitalSignatureEDecode),
    };

    /// <summary>
    /// Windows symbolic cryptographic and trust statuses treated as conclusive validation failures.
    /// The values are defined by <c>WinError.h</c> and documented in
    /// <see href="https://learn.microsoft.com/windows/win32/seccrypto/certificate-and-trust-return-values">Certificate and Trust Return Values</see>.
    /// </summary>
    private enum ValidationStatus : uint
    {
        NteBadSignature = 0x80090006,
        NteBadAlgorithmId = 0x80090008,
        CryptEHashValue = 0x80091007,
        CryptEBadEncode = 0x80092002,
        CryptEBadMessage = 0x8009200D,
        CryptENoSigner = 0x8009200E,
        CryptERevoked = 0x80092010,
        CryptESecuritySettings = 0x80092026,
        TrustENoSignerCertificate = 0x80096002,
        TrustECounterSigner = 0x80096003,
        TrustECertificateSignature = 0x80096004,
        TrustETimeStamp = 0x80096005,
        TrustEBadDigest = 0x80096010,
        TrustEBasicConstraints = 0x80096019,
        TrustEFinancialCriteria = 0x8009601E,
        TrustEProviderUnknown = 0x800B0001,
        TrustEActionUnknown = 0x800B0002,
        TrustESubjectFormUnknown = 0x800B0003,
        TrustESubjectNotTrusted = 0x800B0004,
        DigitalSignatureEEncode = 0x800B0005,
        DigitalSignatureEDecode = 0x800B0006,
    }

    public static bool IsValidationRejection(int status)
    {
        if (status == 0)
        {
            return false;
        }

        uint value = unchecked((uint)status);
        bool isCertificateOrTrustValidationStatus =
            value >= CertificateAndTrustStatusRangeStart
            && value <= CertificateAndTrustStatusRangeEnd;
        bool isMalformedAsn1Status =
            value >= Asn1StatusRangeStart && value <= Asn1StatusRangeEnd;
        return ValidationStatuses.Contains(status)
            || isCertificateOrTrustValidationStatus
            || isMalformedAsn1Status;
    }

    public static bool IsRevocationAvailabilityStatus(int status)
    {
        uint value = unchecked((uint)status);
        return value is CryptENoRevocationCheck
            or CryptERevocationOffline
            or CertERevocationFailure;
    }

    public static Exception CreateUnexpectedException(int status, string operation)
    {
        uint value = unchecked((uint)status);
        string message = $"{operation} with native status 0x{value:X8}.";
        if (value is EOutOfMemory or ErrorNotEnoughMemory or ErrorOutOfMemory)
        {
            return new OutOfMemoryException(message);
        }

        if (value is EInvalidArgument or ErrorInvalidParameter)
        {
            return new InvalidOperationException(message);
        }

        return new ExternalException(message, status);
    }

    public static string Format(int status)
    {
        return $"0x{unchecked((uint)status):X8}";
    }

    private static int Status(uint value)
    {
        return unchecked((int)value);
    }

    private static int Status(ValidationStatus value)
    {
        return unchecked((int)value);
    }
}
