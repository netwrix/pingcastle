using System.ComponentModel;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Netwrix.AuthenticodeVerification.Interop;

internal sealed class StableFile : IDisposable
{
    /// <summary>
    /// The minimum legal managed buffer size for the <see cref="FileStream"/> constructor.
    /// This stream performs no managed reads; it exists to own the stable native handle.
    /// See <see href="https://learn.microsoft.com/dotnet/api/system.io.filestream.-ctor"><c>FileStream</c> constructors</see>.
    /// </summary>
    private const int FileStreamBufferSize = 1;

    /// <summary>
    /// A non-security-sensitive initial capacity for final-path resolution.  Windows returns the
    /// required capacity when this is too small.
    /// See <see href="https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew"><c>GetFinalPathNameByHandleW</c></see>.
    /// </summary>
    private const int InitialFinalPathCapacity = 512;

    private FileStream? stream;

    private StableFile(FileStream stream, string finalPath)
    {
        this.stream = stream;
        FinalPath = finalPath;
    }

    public string FinalPath { get; }

    public bool IsFinalPathUnc => PathValidator.IsUnc(FinalPath);

    public SafeFileHandle Handle => stream?.SafeFileHandle
        ?? throw new ObjectDisposedException(nameof(StableFile));

    public static StableFile Open(string filePath)
    {
        var stream = new FileStream(
            filePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: FileStreamBufferSize,
            FileOptions.None);
        try
        {
            string finalPath = ResolveFinalPath(stream);
            return new StableFile(stream, finalPath);
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    public FileStream TakeStream()
    {
        FileStream ownedStream = stream
            ?? throw new ObjectDisposedException(nameof(StableFile));
        stream = null;
        return ownedStream;
    }

    public void Dispose()
    {
        stream?.Dispose();
        stream = null;
    }

    private static string ResolveFinalPath(FileStream stream)
    {
        // Resolve from the retained handle so a mapped drive or reparse point cannot hide UNC naming.
        // https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew
        var buffer = new StringBuilder(InitialFinalPathCapacity);
        uint result = NativeMethods.GetFinalPathNameByHandle(
            stream.SafeFileHandle,
            buffer,
            (uint)buffer.Capacity,
            NativeMethods.FileNameNormalized | NativeMethods.VolumeNameDos);
        if (result == 0)
        {
            throw new Win32Exception();
        }

        if (result >= buffer.Capacity)
        {
            // On insufficient capacity, the returned size already includes the terminating null.
            buffer = new StringBuilder(checked((int)result));
            result = NativeMethods.GetFinalPathNameByHandle(
                stream.SafeFileHandle,
                buffer,
                (uint)buffer.Capacity,
                NativeMethods.FileNameNormalized | NativeMethods.VolumeNameDos);
            if (result == 0)
            {
                throw new Win32Exception();
            }

            if (result >= buffer.Capacity)
            {
                throw new IOException("The resolved candidate path changed length unexpectedly.");
            }
        }

        if (result == 0 || buffer.Length == 0)
        {
            throw new IOException("Windows returned an empty resolved candidate path.");
        }

        return buffer.ToString();
    }
}
