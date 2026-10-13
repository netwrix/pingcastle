using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace Netwrix.AuthenticodeVerification.Interop;

internal static class ProviderStateInspector
{
    /// <summary>
    /// Windows <c>SGNR_TYPE_TIMESTAMP</c>, identifying a trust-provider signer as the timestamp signer.
    /// See <see href="https://learn.microsoft.com/windows/win32/api/wintrust/ns-wintrust-crypt_provider_sgnr"><c>CRYPT_PROVIDER_SGNR</c></see>.
    /// </summary>
    private const uint TimestampSignerType = 0x00000010;

    /// <summary>
    /// Windows <c>CERT_TRUST_REVOCATION_STATUS_UNKNOWN</c>, indicating that revocation status could not be established.
    /// See <see href="https://learn.microsoft.com/windows/win32/api/wincrypt/ns-wincrypt-cert_trust_status"><c>CERT_TRUST_STATUS</c></see>.
    /// </summary>
    private const uint RevocationStatusUnknown = 0x00000040;

    /// <summary>
    /// Windows <c>CERT_TRUST_IS_OFFLINE_REVOCATION</c>, indicating that the revocation source was offline or stale.
    /// See <see href="https://learn.microsoft.com/windows/win32/api/wincrypt/ns-wincrypt-cert_trust_status"><c>CERT_TRUST_STATUS</c></see>.
    /// </summary>
    private const uint OfflineRevocation = 0x01000000;

    /// <summary>
    /// A POC-defined defensive upper bound for provider-controlled signer, chain, element, and error counts.
    /// Windows exposes these counts through structures such as
    /// <see href="https://learn.microsoft.com/windows/win32/api/wintrust/ns-wintrust-crypt_provider_data"><c>CRYPT_PROVIDER_DATA</c></see>
    /// but does not define a shared maximum.
    /// </summary>
    private const uint MaximumProviderCollectionCount = 1024;

    /// <summary>
    /// A POC-defined 16 MiB defensive allocation limit for a provider-supplied encoded certificate.
    /// See <see href="https://learn.microsoft.com/windows/win32/api/wincrypt/ns-wincrypt-cert_context"><c>CERT_CONTEXT</c></see>.
    /// </summary>
    private const uint MaximumEncodedCertificateSize = 16 * 1024 * 1024;

    /// <summary>
    /// The zero-based index of the primary signer used by
    /// <see href="https://learn.microsoft.com/windows/win32/api/wintrust/nf-wintrust-wthelpergetprovsignerfromchain"><c>WTHelperGetProvSignerFromChain</c></see>.
    /// </summary>
    private const uint PrimarySignerIndex = 0;

    /// <summary>
    /// Win32 <c>FALSE</c> for <c>fCounterSigner</c>, selecting the primary signer rather than a countersigner.
    /// See <see href="https://learn.microsoft.com/windows/win32/api/wintrust/nf-wintrust-wthelpergetprovsignerfromchain"><c>WTHelperGetProvSignerFromChain</c></see>.
    /// </summary>
    private const int SelectPrimarySigner = 0;

    /// <summary>
    /// Win32 <c>TRUE</c> for <c>fCounterSigner</c>, selecting a countersigner associated with the primary signer.
    /// See <see href="https://learn.microsoft.com/windows/win32/api/wintrust/nf-wintrust-wthelpergetprovsignerfromchain"><c>WTHelperGetProvSignerFromChain</c></see>.
    /// </summary>
    private const int SelectCounterSigner = 1;

    /// <summary>
    /// The zero-based index of the first countersigner used by
    /// <see href="https://learn.microsoft.com/windows/win32/api/wintrust/nf-wintrust-wthelpergetprovsignerfromchain"><c>WTHelperGetProvSignerFromChain</c></see>.
    /// </summary>
    private const uint FirstCounterSignerIndex = 0;

    /// <summary>
    /// The zero-based index of the leaf certificate in the accepted signer's chain.
    /// See <see href="https://learn.microsoft.com/windows/win32/api/wintrust/nf-wintrust-wthelpergetprovcertfromchain"><c>WTHelperGetProvCertFromChain</c></see>.
    /// </summary>
    private const uint LeafCertificateIndex = 0;

    /// <summary>
    /// The only <c>CERT_TRUST_STATUS.dwErrorStatus</c> bits permitted by the best-effort
    /// revocation-availability exception.
    /// See <see href="https://learn.microsoft.com/windows/win32/api/wincrypt/ns-wincrypt-cert_trust_status"><c>CERT_TRUST_STATUS</c></see>.
    /// </summary>
    private const uint PermittedRevocationAvailabilityBits =
        RevocationStatusUnknown | OfflineRevocation;

    public static bool TryCopySignerCertificateWithAcceptedTimestamp(
        WinTrustOperation operation,
        out X509Certificate2? certificate)
    {
        if (operation is null)
        {
            throw new ArgumentNullException(nameof(operation));
        }

        if (operation.Status != 0)
        {
            throw new InvalidOperationException(
                "A successful provider state cannot be inspected after WinVerifyTrust rejection.");
        }

        certificate = null;
        if (operation.StateData == IntPtr.Zero)
        {
            throw new InvalidOperationException(
                "WinVerifyTrust reported success without returning provider state.");
        }

        IntPtr providerPointer = NativeMethods.WTHelperProvDataFromStateData(operation.StateData);
        CryptProviderData provider = ReadCheckedStructure<CryptProviderData>(
            providerPointer,
            "CRYPT_PROVIDER_DATA");
        if (provider.OpenedFile != 0)
        {
            throw new InvalidOperationException(
                "The WinTrust provider reopened the candidate instead of using the supplied stable handle.");
        }

        if (provider.Error != 0 || provider.FinalError != 0)
        {
            throw new InvalidOperationException(
                "WinVerifyTrust reported success with a provider error.");
        }

        ValidateTrustStepErrors(provider);
        if (provider.SignerCount == 0 || provider.SignerCount > MaximumProviderCollectionCount)
        {
            throw new InvalidOperationException(
                "WinVerifyTrust reported success without a structurally valid primary signer count.");
        }

        IntPtr primarySignerPointer = NativeMethods.WTHelperGetProvSignerFromChain(
            providerPointer,
            signerIndex: PrimarySignerIndex,
            counterSigner: SelectPrimarySigner,
            counterSignerIndex: FirstCounterSignerIndex);
        CryptProviderSigner primarySigner = ReadCheckedStructure<CryptProviderSigner>(
            primarySignerPointer,
            "primary CRYPT_PROVIDER_SGNR");
        ValidateSuccessfulSigner(primarySigner, requireTimestampSignerType: false);

        if (primarySigner.CounterSignerCount == 0)
        {
            return false;
        }

        if (primarySigner.CounterSignerCount > MaximumProviderCollectionCount)
        {
            throw new InvalidOperationException(
                "The primary signer returned an unreasonable timestamp signer count.");
        }

        IntPtr timestampSignerPointer = NativeMethods.WTHelperGetProvSignerFromChain(
            providerPointer,
            signerIndex: PrimarySignerIndex,
            counterSigner: SelectCounterSigner,
            counterSignerIndex: FirstCounterSignerIndex);
        // The helper binds this countersigner to the primary signer selected by the successful policy state.
        // https://learn.microsoft.com/windows/win32/api/wintrust/nf-wintrust-wthelpergetprovsignerfromchain
        CryptProviderSigner timestampSigner = ReadCheckedStructure<CryptProviderSigner>(
            timestampSignerPointer,
            "timestamp CRYPT_PROVIDER_SGNR");
        ValidateSuccessfulSigner(timestampSigner, requireTimestampSignerType: true);
        if (primarySigner.VerifyAsOf.IsZero)
        {
            throw new InvalidOperationException(
                "The accepted primary signer has no provider-selected verification time.");
        }

        if (primarySigner.CertificateChainCount == 0
            || primarySigner.CertificateChainCount > MaximumProviderCollectionCount)
        {
            throw new InvalidOperationException(
                "The accepted primary signer has an invalid certificate-chain count.");
        }

        IntPtr providerCertificatePointer = NativeMethods.WTHelperGetProvCertFromChain(
            primarySignerPointer,
            certificateIndex: LeafCertificateIndex);
        CryptProviderCertificate providerCertificate =
            ReadCheckedStructure<CryptProviderCertificate>(
                providerCertificatePointer,
                "leaf CRYPT_PROVIDER_CERT");
        if (providerCertificate.Certificate == IntPtr.Zero)
        {
            throw new InvalidOperationException(
                "The accepted primary signer has no leaf certificate context.");
        }

        CertificateContext certificateContext =
            Marshal.PtrToStructure<CertificateContext>(providerCertificate.Certificate);
        if (certificateContext.EncodedCertificate == IntPtr.Zero
            || certificateContext.EncodedCertificateSize == 0
            || certificateContext.EncodedCertificateSize > MaximumEncodedCertificateSize)
        {
            throw new InvalidOperationException(
                "The evaluated leaf certificate has invalid encoded-certificate bounds.");
        }

        var encodedCertificate = new byte[certificateContext.EncodedCertificateSize];
        Marshal.Copy(
            certificateContext.EncodedCertificate,
            encodedCertificate,
            startIndex: 0,
            encodedCertificate.Length);
        // Copy provider-owned bytes while the state is live; the managed certificate owns the copy.
#if NETFRAMEWORK
        certificate = new X509Certificate2(encodedCertificate);
#else
        certificate = X509CertificateLoader.LoadCertificate(encodedCertificate);
#endif
        return true;
    }

    public static bool IsRevocationAvailabilityOnly(WinTrustOperation operation)
    {
        if (operation is null)
        {
            throw new ArgumentNullException(nameof(operation));
        }

        if (!WinTrustStatusClassifier.IsRevocationAvailabilityStatus(operation.Status)
            || operation.StateData == IntPtr.Zero)
        {
            return false;
        }

        IntPtr providerPointer = NativeMethods.WTHelperProvDataFromStateData(operation.StateData);
        if (!TryReadCheckedStructure(providerPointer, out CryptProviderData provider))
        {
            return false;
        }

        if (provider.OpenedFile != 0)
        {
            throw new InvalidOperationException(
                "The WinTrust provider reopened the candidate instead of using the supplied stable handle.");
        }

        // Permit only unknown/offline revocation evidence and reject every unrelated trust bit.
        // https://learn.microsoft.com/windows/win32/api/wincrypt/ns-wincrypt-cert_trust_status
        bool observedAvailabilityFailure = false;
        if (!IsPermittedAvailabilityError(provider.Error, ref observedAvailabilityFailure)
            || !IsPermittedAvailabilityError(provider.FinalError, ref observedAvailabilityFailure)
            || !AreTrustStepErrorsAvailabilityOnly(provider, ref observedAvailabilityFailure)
            || provider.SignerCount == 0
            || provider.SignerCount > MaximumProviderCollectionCount)
        {
            return false;
        }

        IntPtr primaryPointer = NativeMethods.WTHelperGetProvSignerFromChain(
            providerPointer,
            signerIndex: PrimarySignerIndex,
            counterSigner: SelectPrimarySigner,
            counterSignerIndex: FirstCounterSignerIndex);
        if (!TryReadCheckedStructure(primaryPointer, out CryptProviderSigner primary)
            || !IsPermittedAvailabilityError(primary.Error, ref observedAvailabilityFailure)
            || primary.CounterSignerCount == 0
            || primary.CounterSignerCount > MaximumProviderCollectionCount
            || !IsChainAvailabilityOnly(primary.ChainContext, ref observedAvailabilityFailure))
        {
            return false;
        }

        IntPtr timestampPointer = NativeMethods.WTHelperGetProvSignerFromChain(
            providerPointer,
            signerIndex: PrimarySignerIndex,
            counterSigner: SelectCounterSigner,
            counterSignerIndex: FirstCounterSignerIndex);
        if (!TryReadCheckedStructure(timestampPointer, out CryptProviderSigner timestamp)
            || (timestamp.SignerType & TimestampSignerType) == 0
            || !IsPermittedAvailabilityError(timestamp.Error, ref observedAvailabilityFailure)
            || !IsChainAvailabilityOnly(timestamp.ChainContext, ref observedAvailabilityFailure))
        {
            return false;
        }

        return observedAvailabilityFailure;
    }

    private static void ValidateSuccessfulSigner(
        CryptProviderSigner signer,
        bool requireTimestampSignerType)
    {
        if (signer.Error != 0)
        {
            throw new InvalidOperationException(
                "WinVerifyTrust reported success with a signer error.");
        }

        if (requireTimestampSignerType && (signer.SignerType & TimestampSignerType) == 0)
        {
            throw new InvalidOperationException(
                "The associated counter-signer is not marked as a timestamp signer.");
        }

        CertificateChainContext chain = ReadCheckedStructure<CertificateChainContext>(
            signer.ChainContext,
            "CERT_CHAIN_CONTEXT");
        if (chain.ChainCount == 0
            || chain.ChainCount > MaximumProviderCollectionCount
            || chain.Chains == IntPtr.Zero)
        {
            throw new InvalidOperationException(
                "The accepted signer has no structurally valid certificate chain.");
        }
    }

    private static void ValidateTrustStepErrors(CryptProviderData provider)
    {
        if (provider.TrustStepErrorCount > MaximumProviderCollectionCount)
        {
            throw new InvalidOperationException(
                "WinVerifyTrust returned an unreasonable trust-step error count.");
        }

        if (provider.TrustStepErrorCount == 0)
        {
            return;
        }

        if (provider.TrustStepErrors == IntPtr.Zero)
        {
            throw new InvalidOperationException(
                "WinVerifyTrust returned a trust-step count without an error array.");
        }

        for (uint index = 0; index < provider.TrustStepErrorCount; index++)
        {
            int error = Marshal.ReadInt32(
                provider.TrustStepErrors,
                checked((int)index * sizeof(int)));
            if (error != 0)
            {
                throw new InvalidOperationException(
                    "WinVerifyTrust reported success with a trust-step error.");
            }
        }
    }

    private static bool AreTrustStepErrorsAvailabilityOnly(
        CryptProviderData provider,
        ref bool observedAvailabilityFailure)
    {
        if (provider.TrustStepErrorCount > MaximumProviderCollectionCount)
        {
            return false;
        }

        if (provider.TrustStepErrorCount == 0)
        {
            return true;
        }

        if (provider.TrustStepErrors == IntPtr.Zero)
        {
            return false;
        }

        for (uint index = 0; index < provider.TrustStepErrorCount; index++)
        {
            uint error = unchecked((uint)Marshal.ReadInt32(
                provider.TrustStepErrors,
                checked((int)index * sizeof(int))));
            if (!IsPermittedAvailabilityError(error, ref observedAvailabilityFailure))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsChainAvailabilityOnly(
        IntPtr chainContextPointer,
        ref bool observedAvailabilityFailure)
    {
        if (!TryReadCheckedStructure(
                chainContextPointer,
                out CertificateChainContext chainContext)
            || chainContext.ChainCount == 0
            || chainContext.ChainCount > MaximumProviderCollectionCount
            || chainContext.Chains == IntPtr.Zero
            || !IsPermittedTrustStatus(
                chainContext.TrustStatus.ErrorStatus,
                ref observedAvailabilityFailure))
        {
            return false;
        }

        for (uint chainIndex = 0; chainIndex < chainContext.ChainCount; chainIndex++)
        {
            IntPtr simpleChainPointer = Marshal.ReadIntPtr(
                chainContext.Chains,
                checked((int)chainIndex * IntPtr.Size));
            if (!TryReadCheckedStructure(
                    simpleChainPointer,
                    out CertificateSimpleChain simpleChain)
                || simpleChain.ElementCount == 0
                || simpleChain.ElementCount > MaximumProviderCollectionCount
                || simpleChain.Elements == IntPtr.Zero
                || !IsPermittedTrustStatus(
                    simpleChain.TrustStatus.ErrorStatus,
                    ref observedAvailabilityFailure))
            {
                return false;
            }

            for (uint elementIndex = 0; elementIndex < simpleChain.ElementCount; elementIndex++)
            {
                IntPtr elementPointer = Marshal.ReadIntPtr(
                    simpleChain.Elements,
                    checked((int)elementIndex * IntPtr.Size));
                if (!TryReadCheckedStructure(
                        elementPointer,
                        out CertificateChainElement element)
                    || !IsPermittedTrustStatus(
                        element.TrustStatus.ErrorStatus,
                        ref observedAvailabilityFailure))
                {
                    return false;
                }
            }
        }

        return true;
    }

    private static bool IsPermittedAvailabilityError(
        uint error,
        ref bool observedAvailabilityFailure)
    {
        if (error == 0)
        {
            return true;
        }

        if (!WinTrustStatusClassifier.IsRevocationAvailabilityStatus(unchecked((int)error)))
        {
            return false;
        }

        observedAvailabilityFailure = true;
        return true;
    }

    private static bool IsPermittedTrustStatus(
        uint errorStatus,
        ref bool observedAvailabilityFailure)
    {
        if ((errorStatus & ~PermittedRevocationAvailabilityBits) != 0)
        {
            return false;
        }

        if ((errorStatus & PermittedRevocationAvailabilityBits) != 0)
        {
            observedAvailabilityFailure = true;
        }

        return true;
    }

    private static T ReadCheckedStructure<T>(IntPtr pointer, string structureName)
        where T : struct
    {
        if (pointer == IntPtr.Zero)
        {
            throw new InvalidOperationException($"WinTrust returned no {structureName}.");
        }

        int expectedSize = Marshal.SizeOf(typeof(T));
        uint returnedSize = unchecked((uint)Marshal.ReadInt32(pointer));
        if (returnedSize != expectedSize)
        {
            throw new PlatformNotSupportedException(
                $"WinTrust returned {structureName} size {returnedSize}; expected {expectedSize}.");
        }

        return Marshal.PtrToStructure<T>(pointer);
    }

    private static bool TryReadCheckedStructure<T>(IntPtr pointer, out T value)
        where T : struct
    {
        if (pointer == IntPtr.Zero)
        {
            value = default;
            return false;
        }

        int expectedSize = Marshal.SizeOf(typeof(T));
        uint returnedSize = unchecked((uint)Marshal.ReadInt32(pointer));
        if (returnedSize != expectedSize)
        {
            throw new PlatformNotSupportedException(
                $"WinTrust returned {typeof(T).Name} size {returnedSize}; expected {expectedSize}.");
        }

        value = Marshal.PtrToStructure<T>(pointer);
        return true;
    }
}
