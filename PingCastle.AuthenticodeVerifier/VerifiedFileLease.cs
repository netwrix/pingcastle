using System.Threading;

namespace Netwrix.AuthenticodeVerification;

/// <summary>
/// Retains ownership of the exact file object that successfully passed Authenticode verification.
/// </summary>
/// <remarks>
/// Keep this lease alive until all trusted use of the verified file has completed.  While the
/// lease is alive, the file cannot be modified, deleted, or replaced through normal Windows file
/// operations.  The lease does not protect the containing directory namespace.
/// </remarks>
public sealed class VerifiedFileLease : IDisposable
{
    private FileStream? stream;

    internal VerifiedFileLease(FileStream stream)
    {
        this.stream = stream ?? throw new ArgumentNullException(nameof(stream));
    }

    /// <summary>
    /// Releases the retained file handle after trusted use of the verified file is complete.
    /// </summary>
    /// <remarks>
    /// This method is idempotent and may be called more than once.
    /// </remarks>
    public void Dispose()
    {
        Interlocked.Exchange(ref stream, null)?.Dispose();
    }
}
