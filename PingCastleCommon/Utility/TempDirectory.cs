namespace PingCastleCommon.Utility;

/// <summary>
/// A newly created, empty temporary directory that is deleted with everything in it when this object is
/// disposed; use it in a using statement. Failing to delete it is ignored.
/// </summary>
public sealed class TempDirectory : IDisposable
{
    public string FullPath { get; } = Directory.CreateTempSubdirectory("PingCastle-").FullName;

    public void Dispose()
    {
        try
        {
            Directory.Delete(FullPath, recursive: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
    }
}
