namespace PingCastle.misc
{
    /// <summary>
    /// Verifies that release executables carry a valid PingCastle signature before they are
    /// packaged for download.
    /// </summary>
    public interface IReleaseSignatureVerifier
    {
        /// <summary>
        /// Verifies the Authenticode signature of the file at <paramref name="filePath"/>.
        /// </summary>
        /// <param name="filePath">Full path of the file to verify.</param>
        /// <returns>True only when the file exists and carries a valid PingCastle signature.</returns>
        bool VerifySignature(string filePath);

        /// <summary>
        /// Verifies the Authenticode signature of the file at <paramref name="filePath"/> and
        /// returns the lease that keeps the verified file locked against modification.
        /// </summary>
        /// <param name="filePath">Full path of the file to verify.</param>
        /// <param name="lease">Lease to dispose once the file has been consumed. Null when verification fails.</param>
        /// <returns>True only when the file exists and carries a valid PingCastle signature.</returns>
        bool VerifySignature(string filePath, out System.IDisposable lease);
    }
}
