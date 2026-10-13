namespace PingCastle.misc
{
    using System.IO;
    using System.Runtime.Versioning;
    using Netwrix.AuthenticodeVerification;

    /// <summary>
    /// Default <see cref="IReleaseSignatureVerifier"/> backed by <see cref="WindowsTrustChecker"/>.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public class ReleaseSignatureVerifier : IReleaseSignatureVerifier
    {
        /// <summary>
        /// Verifies that the file at <paramref name="filePath"/> carries a valid Authenticode
        /// signature from an approved Netwrix signing key. Fails closed: any rejection or
        /// verification error returns false.
        /// </summary>
        /// <param name="filePath">Full path of the file to verify. No path rewriting is performed.</param>
        /// <returns>True only when the signature is trusted and the signing key is approved.</returns>
        public bool VerifySignature(string filePath)
        {
            if (!VerifySignature(filePath, out System.IDisposable lease))
            {
                return false;
            }

            // Callers of this overload do not consume the file, so release the lease immediately.
            lease.Dispose();
            return true;
        }

        /// <summary>
        /// As <see cref="VerifySignature(string)"/>, but hands the lease to the caller, who must
        /// dispose it once the verified file has been consumed.
        /// </summary>
        public bool VerifySignature(string filePath, out System.IDisposable lease)
        {
            lease = null;
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
            {
                return false;
            }

            if (!WindowsTrustChecker.TryVerifyPingCastleSignature(filePath, RevocationPolicy.OnlineBestEffort, out VerifiedFileLease verifiedLease))
            {
                return false;
            }

            lease = verifiedLease;
            return true;
        }
    }
}
