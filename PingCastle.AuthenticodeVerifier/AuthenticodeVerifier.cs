namespace PingCastle.AuthenticodeVerifier;

using Microsoft.Extensions.Logging;
using Netwrix.AuthenticodeVerification;
using Netwrix.AuthenticodeVerification.Cryptography;
using Netwrix.AuthenticodeVerification.Interop;

/// <summary>
/// Validates a local file using Windows Authenticode policy and requires the accepted
/// signer to use an approved Netwrix signing key.
/// </summary>
/// <remarks>
/// <para>
/// A candidate remains untrusted unless <see cref="Verify"/> returns <see langword="true"/>.
/// The caller must retain the returned <see cref="VerifiedFileLease"/> until all trusted
/// use of the validated file has completed.
/// </para>
/// <para>
/// Instances do not retain per-verification state and may be used concurrently.
/// This verifier establishes file authenticity; it does not decide whether the authenticated
/// file is authorised for a caller's particular operation.
/// </para>
/// </remarks>
public sealed class AuthenticodeVerifier
{
    /// <summary>
    /// POC-local stable event 1000, emitted when verification starts.
    /// See <see href="https://learn.microsoft.com/dotnet/api/microsoft.extensions.logging.eventid"><c>EventId</c></see>.
    /// </summary>
    private static readonly EventId VerificationStartedEvent =
        new(1000, "VerificationStarted");

    /// <summary>
    /// POC-local stable event 1001, emitted when verification succeeds without degraded revocation assurance.
    /// See <see href="https://learn.microsoft.com/dotnet/api/microsoft.extensions.logging.eventid"><c>EventId</c></see>.
    /// </summary>
    private static readonly EventId VerificationSucceededEvent =
        new(1001, "VerificationSucceeded");

    /// <summary>
    /// POC-local stable event 1002, emitted when validation completes with a conclusive rejection.
    /// See <see href="https://learn.microsoft.com/dotnet/api/microsoft.extensions.logging.eventid"><c>EventId</c></see>.
    /// </summary>
    private static readonly EventId VerificationRejectedEvent =
        new(1002, "VerificationRejected");

    /// <summary>
    /// POC-local stable event 1003, emitted when best-effort verification succeeds without established revocation status.
    /// See <see href="https://learn.microsoft.com/dotnet/api/microsoft.extensions.logging.eventid"><c>EventId</c></see>.
    /// </summary>
    private static readonly EventId VerificationSucceededWithUnknownRevocationEvent =
        new(1003, "VerificationSucceededWithUnknownRevocation");

    private static readonly Action<ILogger, RevocationPolicy, Exception?> LogVerificationStarted =
        LoggerMessage.Define<RevocationPolicy>(
            LogLevel.Debug,
            VerificationStartedEvent,
            "Authenticode verification started with revocation policy {RevocationPolicy}.");

    private static readonly Action<ILogger, RevocationPolicy, string, Exception?> LogVerificationRejected =
        LoggerMessage.Define<RevocationPolicy, string>(
            LogLevel.Information,
            VerificationRejectedEvent,
            "Authenticode verification rejected the candidate under policy {RevocationPolicy} at stage {RejectionStage}.");

    private static readonly Action<ILogger, RevocationPolicy, string, string, Exception?> LogNativeVerificationRejected =
        LoggerMessage.Define<RevocationPolicy, string, string>(
            LogLevel.Information,
            VerificationRejectedEvent,
            "Authenticode verification rejected the candidate under policy {RevocationPolicy} at stage {RejectionStage} with native status {NativeStatus}.");

    private static readonly Action<ILogger, RevocationPolicy, Exception?> LogVerificationSucceeded =
        LoggerMessage.Define<RevocationPolicy>(
            LogLevel.Information,
            VerificationSucceededEvent,
            "Authenticode verification succeeded under revocation policy {RevocationPolicy}.");

    private static readonly Action<ILogger, RevocationPolicy, Exception?> LogVerificationSucceededWithUnknownRevocation =
        LoggerMessage.Define<RevocationPolicy>(
            LogLevel.Warning,
            VerificationSucceededWithUnknownRevocationEvent,
            "Authenticode verification succeeded under best-effort policy {RevocationPolicy}, but revocation status was not established.");

    private readonly ILogger<AuthenticodeVerifier> logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="AuthenticodeVerifier"/> class.
    /// </summary>
    /// <param name="logger">
    /// The logger that receives non-sensitive validation decisions and diagnostic context.
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="logger"/> is <see langword="null"/>.
    /// </exception>
    public AuthenticodeVerifier(ILogger<AuthenticodeVerifier> logger)
    {
        this.logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Validates the file identified by an absolute local path and, when accepted, returns
    /// a lease that keeps the validated file object stable.
    /// </summary>
    /// <param name="filePath">
    /// The fully qualified path to an existing local file.  Relative paths and UNC paths
    /// are not accepted.
    /// </param>
    /// <param name="verificationLease">
    /// When this method returns <see langword="true"/>, receives the lease that the caller
    /// must retain until trusted use is complete.  When this method returns
    /// <see langword="false"/>, receives <see langword="null"/>.
    /// </param>
    /// <param name="revocationPolicy">
    /// The revocation policy for this operation.  A <see langword="null"/> value selects
    /// <see cref="RevocationPolicy.OnlineStrict"/> inside this method.
    /// </param>
    /// <returns>
    /// <see langword="true"/> only when Windows accepts the embedded Authenticode signature
    /// and timestamp and the accepted signer uses an approved Netwrix key; otherwise,
    /// <see langword="false"/> when validation completed with a conclusive rejection.
    /// </returns>
    /// <remarks>
    /// <para>
    /// This method does not use exceptions for an ordinary validation rejection.  It throws
    /// when validation cannot produce a trustworthy yes-or-no result, including when the file
    /// cannot be opened or an unexpected native failure occurs.
    /// </para>
    /// <para>
    /// The returned lease prevents modification, deletion, and same-path replacement of the
    /// opened file while it is held.  It does not protect the containing directory namespace;
    /// callers must satisfy the documented usage requirements before acting on the path.
    /// </para>
    /// </remarks>
    /// <example>
    /// <code>
    /// if (!verifier.Verify(
    ///         candidatePath,
    ///         out VerifiedFileLease? lease,
    ///         RevocationPolicy.OnlineBestEffort))
    /// {
    ///     return;
    /// }
    ///
    /// using (lease!)
    /// {
    ///     ExecuteVerifiedFile(candidatePath);
    /// }
    /// </code>
    /// </example>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="filePath"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="filePath"/> is empty, contains only white space, is malformed, or is
    /// not fully qualified and absolute.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="revocationPolicy"/> is not a defined <see cref="RevocationPolicy"/> value.
    /// </exception>
    /// <exception cref="FileNotFoundException">
    /// The candidate file does not exist.
    /// </exception>
    /// <exception cref="DirectoryNotFoundException">
    /// A component of the candidate path does not exist.
    /// </exception>
    /// <exception cref="UnauthorizedAccessException">
    /// The process is not authorised to open the candidate file for verification.
    /// </exception>
    /// <exception cref="IOException">
    /// The candidate cannot be opened with the required sharing constraints, its final path
    /// cannot be resolved reliably, or the retained file handle cannot be used safely.
    /// </exception>
    /// <exception cref="PlatformNotSupportedException">
    /// The Windows trust-provider structures do not have a layout understood by this implementation.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Windows returns an unexpected or internally inconsistent trust-provider state.
    /// </exception>
    /// <exception cref="System.Runtime.InteropServices.ExternalException">
    /// Windows returns an unrecognised native status for which no safe validation result can be produced.
    /// </exception>
    public bool Verify(
        string filePath,
        out VerifiedFileLease? verificationLease,
        RevocationPolicy? revocationPolicy = null)
    {
        verificationLease = null;
        RevocationPolicy effectivePolicy = revocationPolicy ?? RevocationPolicy.OnlineStrict;

        if (!Enum.IsDefined(typeof(RevocationPolicy), effectivePolicy))
        {
            throw new ArgumentOutOfRangeException(nameof(revocationPolicy));
        }

        bool suppliedPathIsUnc = PathValidator.ValidateAndIsUnc(filePath);
        LogVerificationStarted(logger, effectivePolicy, null);
        if (suppliedPathIsUnc)
        {
            LogVerificationRejected(logger, effectivePolicy, "SuppliedUncPath", null);
            return false;
        }

        using StableFile stableFile = StableFile.Open(filePath);
        if (stableFile.IsFinalPathUnc)
        {
            LogVerificationRejected(logger, effectivePolicy, "ResolvedUncPath", null);
            return false;
        }

        VerificationDecision decision = EvaluateStableFile(stableFile, effectivePolicy);
        if (!decision.Accepted)
        {
            if (decision.NativeStatus is int nativeStatus)
            {
                LogNativeVerificationRejected(
                    logger,
                    effectivePolicy,
                    decision.Stage,
                    WinTrustStatusClassifier.Format(nativeStatus),
                    null);
            }
            else
            {
                LogVerificationRejected(logger, effectivePolicy, decision.Stage, null);
            }

            return false;
        }

        var lease = new VerifiedFileLease(stableFile.TakeStream());
        try
        {
            if (decision.Degraded)
            {
                LogVerificationSucceededWithUnknownRevocation(logger, effectivePolicy, null);
            }
            else
            {
                LogVerificationSucceeded(logger, effectivePolicy, null);
            }

            verificationLease = lease;
            return true;
        }
        catch
        {
            lease.Dispose();
            throw;
        }
    }

    private static VerificationDecision EvaluateStableFile(
        StableFile stableFile,
        RevocationPolicy effectivePolicy)
    {
        WinTrustOperation? operation = null;
        Exception? pendingException = null;
        try
        {
            operation = WinTrustOperation.Verify(
                stableFile.Handle,
                stableFile.FinalPath,
                effectivePolicy);
            // WinVerifyTrust returns a LONG; only exact zero is policy success.
            // https://learn.microsoft.com/windows/win32/api/wintrust/nf-wintrust-winverifytrust
            if (operation.Status != 0)
            {
                if (!WinTrustStatusClassifier.IsValidationRejection(operation.Status))
                {
                    throw WinTrustStatusClassifier.CreateUnexpectedException(
                        operation.Status,
                        "WinVerifyTrust failed");
                }

                if (IsBestEffort(effectivePolicy)
                    && WinTrustStatusClassifier.IsRevocationAvailabilityStatus(operation.Status)
                    && ProviderStateInspector.IsRevocationAvailabilityOnly(operation))
                {
                    return EvaluateBestEffortConfirmation(stableFile, effectivePolicy);
                }

                return VerificationDecision.Rejected("WindowsAuthenticodePolicy", operation.Status);
            }

            return EvaluateSuccessfulOperation(operation, degraded: false);
        }
        catch (Exception exception)
        {
            pendingException = exception;
            throw;
        }
        finally
        {
            operation?.Dispose(suppressCloseFailure: pendingException is not null);
        }
    }

    private static VerificationDecision EvaluateBestEffortConfirmation(
        StableFile stableFile,
        RevocationPolicy effectivePolicy)
    {
        WinTrustOperation? operation = null;
        Exception? pendingException = null;
        try
        {
            operation = WinTrustOperation.Verify(
                stableFile.Handle,
                stableFile.FinalPath,
                effectivePolicy,
                checkRevocation: false);
            if (operation.Status != 0)
            {
                if (!WinTrustStatusClassifier.IsValidationRejection(operation.Status))
                {
                    throw WinTrustStatusClassifier.CreateUnexpectedException(
                        operation.Status,
                        "The best-effort WinVerifyTrust confirmation pass failed");
                }

                return VerificationDecision.Rejected(
                    "BestEffortConfirmationPolicy",
                    operation.Status);
            }

            return EvaluateSuccessfulOperation(operation, degraded: true);
        }
        catch (Exception exception)
        {
            pendingException = exception;
            throw;
        }
        finally
        {
            operation?.Dispose(suppressCloseFailure: pendingException is not null);
        }
    }

    private static VerificationDecision EvaluateSuccessfulOperation(
        WinTrustOperation operation,
        bool degraded)
    {
        if (!ProviderStateInspector.TryCopySignerCertificateWithAcceptedTimestamp(
                operation,
                out System.Security.Cryptography.X509Certificates.X509Certificate2? certificate))
        {
            return VerificationDecision.Rejected("AcceptedTimestamp");
        }

        if (certificate is null)
        {
            throw new InvalidOperationException(
                "Provider-state inspection succeeded without copying a signer certificate.");
        }

        using (certificate)
        {
            if (!ApprovedSigningKeyVerifier.IsApproved(certificate))
            {
                return VerificationDecision.Rejected("ApprovedSigningKey");
            }

            return VerificationDecision.Success(degraded);
        }
    }

    private static bool IsBestEffort(RevocationPolicy policy)
    {
        return policy is RevocationPolicy.OnlineBestEffort
            or RevocationPolicy.CacheOnlyBestEffort;
    }

    private readonly struct VerificationDecision
    {
        private VerificationDecision(
            bool accepted,
            bool degraded,
            string stage,
            int? nativeStatus)
        {
            Accepted = accepted;
            Degraded = degraded;
            Stage = stage;
            NativeStatus = nativeStatus;
        }

        public bool Accepted { get; }

        public bool Degraded { get; }

        public string Stage { get; }

        public int? NativeStatus { get; }

        public static VerificationDecision Success(bool degraded)
        {
            return new VerificationDecision(true, degraded, string.Empty, null);
        }

        public static VerificationDecision Rejected(string stage, int? nativeStatus = null)
        {
            return new VerificationDecision(false, false, stage, nativeStatus);
        }
    }
}
