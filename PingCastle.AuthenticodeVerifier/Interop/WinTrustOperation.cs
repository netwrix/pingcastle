using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Netwrix.AuthenticodeVerification.Interop;

internal sealed class WinTrustOperation : IDisposable
{
    /// <summary>
    /// Windows <c>CERT_STRONG_SIGN_OID_INFO_CHOICE</c>, selecting the OID member of
    /// <see href="https://learn.microsoft.com/windows/win32/api/wincrypt/ns-wincrypt-cert_strong_sign_para"><c>CERT_STRONG_SIGN_PARA</c></see>.
    /// </summary>
    private const uint CertStrongSignOidInfoChoice = 2;

    /// <summary>
    /// Windows <c>WTD_UI_NONE</c>, which prevents the trust provider from displaying UI.
    /// See <see href="https://learn.microsoft.com/windows/win32/api/wintrust/ns-wintrust-wintrust_data"><c>WINTRUST_DATA</c></see>.
    /// </summary>
    private const uint WinTrustUiNone = 2;

    /// <summary>
    /// Windows <c>WTD_REVOKE_NONE</c>, which requests no additional revocation checking.
    /// See <see href="https://learn.microsoft.com/windows/win32/api/wintrust/ns-wintrust-wintrust_data"><c>WINTRUST_DATA</c></see>.
    /// </summary>
    private const uint WinTrustRevokeNone = 0;

    /// <summary>
    /// Windows <c>WTD_REVOKE_WHOLECHAIN</c>, which requests revocation checking for the whole chain.
    /// See <see href="https://learn.microsoft.com/windows/win32/api/wintrust/ns-wintrust-wintrust_data"><c>WINTRUST_DATA</c></see>.
    /// </summary>
    private const uint WinTrustRevokeWholeChain = 0x00000001;

    /// <summary>
    /// Windows <c>WTD_CHOICE_FILE</c>, selecting the <c>pFile</c> member of the trust-data union.
    /// See <see href="https://learn.microsoft.com/windows/win32/api/wintrust/ns-wintrust-wintrust_data"><c>WINTRUST_DATA</c></see>.
    /// </summary>
    private const uint WinTrustChoiceFile = 1;

    /// <summary>
    /// Windows <c>WTD_STATEACTION_VERIFY</c>, which creates provider state for later inspection and closure.
    /// See <see href="https://learn.microsoft.com/windows/win32/api/wintrust/ns-wintrust-wintrust_data"><c>WINTRUST_DATA</c></see>.
    /// </summary>
    private const uint WinTrustStateActionVerify = 1;

    /// <summary>
    /// Windows <c>WTD_STATEACTION_CLOSE</c>, which releases state created by <c>WTD_STATEACTION_VERIFY</c>.
    /// See <see href="https://learn.microsoft.com/windows/win32/api/wintrust/ns-wintrust-wintrust_data"><c>WINTRUST_DATA</c></see>.
    /// </summary>
    private const uint WinTrustStateActionClose = 2;

    /// <summary>
    /// Windows <c>WTD_REVOCATION_CHECK_NONE</c>, disabling trust-provider revocation checking.
    /// See <see href="https://learn.microsoft.com/windows/win32/api/wintrust/ns-wintrust-wintrust_data"><c>WINTRUST_DATA</c></see>.
    /// </summary>
    private const uint WinTrustRevocationCheckNone = 0x00000010;

    /// <summary>
    /// Windows <c>WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT</c>, checking the chain except its trust anchor.
    /// See <see href="https://learn.microsoft.com/windows/win32/api/wintrust/ns-wintrust-wintrust_data"><c>WINTRUST_DATA</c></see>.
    /// </summary>
    private const uint WinTrustRevocationCheckChainExcludeRoot = 0x00000080;

    /// <summary>
    /// Windows <c>WTD_CACHE_ONLY_URL_RETRIEVAL</c>, preventing network retrieval during revocation checks.
    /// See <see href="https://learn.microsoft.com/windows/win32/api/wintrust/ns-wintrust-wintrust_data"><c>WINTRUST_DATA</c></see>.
    /// </summary>
    private const uint WinTrustCacheOnlyUrlRetrieval = 0x00001000;

    /// <summary>
    /// Windows <c>WSS_VERIFY_SPECIFIC</c>, requiring validation of the signature selected by index.
    /// See <see href="https://learn.microsoft.com/windows/win32/api/wintrust/ns-wintrust-wintrust_signature_settings"><c>WINTRUST_SIGNATURE_SETTINGS</c></see>.
    /// </summary>
    private const uint WinTrustSignatureVerifySpecific = 0x00000001;

    /// <summary>
    /// The zero-based index of the primary embedded signature selected by <c>WSS_VERIFY_SPECIFIC</c>.
    /// See <see href="https://learn.microsoft.com/windows/win32/api/wintrust/ns-wintrust-wintrust_signature_settings"><c>WINTRUST_SIGNATURE_SETTINGS</c></see>.
    /// </summary>
    private const uint PrimarySignatureIndex = 0;

    /// <summary>
    /// Windows <c>WTD_UICONTEXT_EXECUTE</c>, the default UI context for a file intended for execution.
    /// See <see href="https://learn.microsoft.com/windows/win32/api/wintrust/ns-wintrust-wintrust_data"><c>WINTRUST_DATA</c></see>.
    /// </summary>
    private const uint WinTrustUiContextExecute = 0;

    /// <summary>
    /// Windows <c>szOID_CERT_STRONG_SIGN_OS_CURRENT</c>, currently the documented OS strong-signature
    /// policy that accepts SHA-2 but rejects SHA-1 and weaker hashes.
    /// See <see href="https://learn.microsoft.com/windows/win32/api/wincrypt/ns-wincrypt-cert_strong_sign_para"><c>CERT_STRONG_SIGN_PARA</c></see>.
    /// </summary>
    private const string StrongSignaturePolicyOid = "1.3.6.1.4.1.311.72.1.1";

    /// <summary>
    /// Windows <c>INVALID_HANDLE_VALUE</c> for the <c>hwnd</c> argument, declaring that no interactive
    /// user is available to assist the trust decision.
    /// See <see href="https://learn.microsoft.com/windows/win32/api/wintrust/nf-wintrust-winverifytrust"><c>WinVerifyTrust</c></see>.
    /// </summary>
    private static readonly IntPtr NoInteractiveUserWindow = new(-1);

    private readonly List<IntPtr> allocations = new();
    private readonly SafeFileHandle fileHandle;
    private bool handleReferenceAdded;
    private bool verifyCallReturned;
    private bool disposed;
    private IntPtr trustDataPointer;

    private WinTrustOperation(
        SafeFileHandle fileHandle,
        string finalPath,
        RevocationPolicy policy,
        bool checkRevocation)
    {
        this.fileHandle = fileHandle ?? throw new ArgumentNullException(nameof(fileHandle));
        try
        {
            NativeLayout.Validate();
            if (fileHandle.IsClosed || fileHandle.IsInvalid)
            {
                throw new ObjectDisposedException(nameof(fileHandle));
            }

            bool addReferenceSucceeded = false;
            // The request embeds the raw handle, so retain it across VERIFY, inspection, and CLOSE.
            fileHandle.DangerousAddRef(ref addReferenceSucceeded);
            handleReferenceAdded = addReferenceSucceeded;
            if (!handleReferenceAdded)
            {
                throw new IOException("The stable candidate handle could not be retained.");
            }

            BuildRequest(finalPath, policy, checkRevocation);
            Guid actionId = NativeMethods.WinTrustActionGenericVerifyV2;
            Status = NativeMethods.WinVerifyTrust(
                NoInteractiveUserWindow,
                ref actionId,
                trustDataPointer);
            verifyCallReturned = true;
            WinTrustData returnedData = Marshal.PtrToStructure<WinTrustData>(trustDataPointer);
            StateData = returnedData.StateData;
        }
        catch
        {
            Dispose(suppressCloseFailure: true);
            throw;
        }
    }

    public int Status { get; }

    public IntPtr StateData { get; }

    public static WinTrustOperation Verify(
        SafeFileHandle fileHandle,
        string finalPath,
        RevocationPolicy policy,
        bool checkRevocation = true)
    {
        return new WinTrustOperation(fileHandle, finalPath, policy, checkRevocation);
    }

    public void Dispose()
    {
        Dispose(suppressCloseFailure: false);
    }

    public void Dispose(bool suppressCloseFailure)
    {
        if (disposed)
        {
            return;
        }

        disposed = true;
        Exception? closeException = null;
        try
        {
            if (verifyCallReturned)
            {
                WinTrustData closeData = Marshal.PtrToStructure<WinTrustData>(trustDataPointer);
                closeData.StateAction = WinTrustStateActionClose;
                Marshal.StructureToPtr(closeData, trustDataPointer, fDeleteOld: false);
                Guid actionId = NativeMethods.WinTrustActionGenericVerifyV2;
                int closeStatus = NativeMethods.WinVerifyTrust(
                    NoInteractiveUserWindow,
                    ref actionId,
                    trustDataPointer);
                if (closeStatus != 0 && !suppressCloseFailure)
                {
                    closeException = WinTrustStatusClassifier.CreateUnexpectedException(
                        closeStatus,
                        "WinVerifyTrust state closure failed");
                }
            }
        }
        catch (Exception exception) when (suppressCloseFailure)
        {
            _ = exception;
        }
        finally
        {
            for (int index = allocations.Count - 1; index >= 0; index--)
            {
                Marshal.FreeHGlobal(allocations[index]);
            }

            allocations.Clear();
            trustDataPointer = IntPtr.Zero;
            if (handleReferenceAdded)
            {
                fileHandle.DangerousRelease();
                handleReferenceAdded = false;
            }
        }

        if (closeException is not null)
        {
            throw closeException;
        }
    }

    private void BuildRequest(string finalPath, RevocationPolicy policy, bool checkRevocation)
    {
        // Every pointer in this graph remains live until the matching WTD_STATEACTION_CLOSE returns.
        // https://learn.microsoft.com/windows/win32/api/wintrust/ns-wintrust-wintrust_data
        IntPtr strongPolicyOid = AllocateStringAnsi(StrongSignaturePolicyOid);
        IntPtr strongParameters = AllocateStructure(new CertStrongSignParameters
        {
            Size = checked((uint)Marshal.SizeOf(typeof(CertStrongSignParameters))),
            InformationChoice = CertStrongSignOidInfoChoice,
            Information = strongPolicyOid,
        });
        IntPtr signatureSettings = AllocateStructure(new WinTrustSignatureSettings
        {
            Size = checked((uint)Marshal.SizeOf(typeof(WinTrustSignatureSettings))),
            Index = PrimarySignatureIndex,
            Flags = WinTrustSignatureVerifySpecific,
            CryptoPolicy = strongParameters,
        });
        IntPtr path = AllocateStringUnicode(finalPath);
        IntPtr fileInfo = AllocateStructure(new WinTrustFileInfo
        {
            Size = checked((uint)Marshal.SizeOf(typeof(WinTrustFileInfo))),
            FilePath = path,
            FileHandle = fileHandle.DangerousGetHandle(),
            // Null lets Windows select the subject provider; PE and MSI are proven by public tests.
            KnownSubject = IntPtr.Zero,
        });

        // Whole-chain checking excludes only the trust anchor.  Cache-only additionally blocks URL retrieval.
        uint providerFlags = checkRevocation
            ? WinTrustRevocationCheckChainExcludeRoot
            : WinTrustRevocationCheckNone;
        if (policy is RevocationPolicy.CacheOnlyStrict or RevocationPolicy.CacheOnlyBestEffort)
        {
            providerFlags |= WinTrustCacheOnlyUrlRetrieval;
        }

        trustDataPointer = AllocateStructure(new WinTrustData
        {
            Size = checked((uint)Marshal.SizeOf(typeof(WinTrustData))),
            UiChoice = WinTrustUiNone,
            RevocationChecks = checkRevocation ? WinTrustRevokeWholeChain : WinTrustRevokeNone,
            UnionChoice = WinTrustChoiceFile,
            FileInfo = fileInfo,
            StateAction = WinTrustStateActionVerify,
            ProviderFlags = providerFlags,
            UiContext = WinTrustUiContextExecute,
            SignatureSettings = signatureSettings,
        });
        // WTD_LIFETIME_SIGNING_FLAG is deliberately absent to preserve normal timestamp semantics.
    }

    private IntPtr AllocateStringAnsi(string value)
    {
        IntPtr pointer = Marshal.StringToHGlobalAnsi(value);
        allocations.Add(pointer);
        return pointer;
    }

    private IntPtr AllocateStringUnicode(string value)
    {
        IntPtr pointer = Marshal.StringToHGlobalUni(value);
        allocations.Add(pointer);
        return pointer;
    }

    private IntPtr AllocateStructure<T>(T value)
        where T : struct
    {
        IntPtr pointer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(T)));
        allocations.Add(pointer);
        Marshal.StructureToPtr(value, pointer, fDeleteOld: false);
        return pointer;
    }
}
