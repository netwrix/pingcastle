namespace PingCastle.misc
{
    /// <summary>
    /// Fail-closed <see cref="IReleaseSignatureVerifier"/> for non-Windows hosts, where
    /// Authenticode verification is unavailable.
    /// </summary>
    public class NullReleaseSignatureVerifier : IReleaseSignatureVerifier
    {
        public bool VerifySignature(string filePath)
        {
            return false;
        }

        public bool VerifySignature(string filePath, out System.IDisposable lease)
        {
            lease = null;
            return false;
        }
    }
}
