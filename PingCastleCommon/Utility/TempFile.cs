namespace PingCastleCommon.Utility;

/// <summary>
/// A newly created, empty temporary file that is deleted when this object is disposed; use it in a using
/// statement. Failing to delete it (for example while antivirus holds it) is ignored.
/// FileOptions.DeleteOnClose is no substitute when another component must open the file by path: the handle
/// holds delete rights, which blocks components that do not share delete, such as the Authenticode check.
/// </summary>
public sealed class TempFile : IDisposable
{
    public string FullPath { get; } = Path.GetTempFileName();

    public void Dispose()
    {
        try
        {
            File.Delete(FullPath);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
    }
}
