#nullable enable

namespace Netwrix.ArchiveVerification;

using System.Diagnostics;
using System.IO.Compression;
using System.Linq;
using PingCastleCommon;
using PingCastleCommon.Utility;

/// <summary>
/// Installs zip entries into a directory, all or nothing: a file that already exists is backed up first, and
/// if any file fails, everything installed so far is rolled back. A file that is in use (for example the
/// running updater) cannot be overwritten but can be swapped, so File.Replace moves it aside as name.bak.
/// The entries are normally those of a <see cref="VerifiedArchive"/>, which must stay open until this returns.
/// </summary>
public static class ArchiveInstaller
{
    /// <summary>
    /// The signed console package, kept unchanged in <see cref="PackageDirectory"/> for other installations to update
    /// from, and the name it is served under.
    /// </summary>
    public const string PackageFileName = "PingCastle.package.zip";

    /// <summary>
    /// The folder next to PingCastle.exe that holds <see cref="PackageFileName"/>.
    /// </summary>
    public const string PackageDirectory = "package";

    /// <summary>
    /// The only files installed from a package downloaded from another installation, whatever else it holds.
    /// </summary>
    public static readonly string[] ConsoleExecutables = { "PingCastle.exe", "PingCastleAutoUpdater.exe" };

    /// <summary>
    /// Installs the entries into <paramref name="targetDirectory"/>, keeping their relative paths. Any failure
    /// rolls the installation back and throws <see cref="ArchiveVerificationException"/>.
    /// </summary>
    public static void Install(IEnumerable<ZipArchiveEntry> entries, string targetDirectory)
    {
        using var backups = new TempDirectory();
        var installed = new List<(string Destination, string? Backup)>();
        var current = string.Empty;

        try
        {
            entries.ToList().ForEach(entry =>
            {
                current = FilesValidator.CheckPathTraversal(entry.FullName, targetDirectory);
                var backup = File.Exists(current) ? Path.Combine(backups.FullPath, $"backup_{installed.Count}") : null;
                if (backup is not null)
                {
                    File.Copy(current, backup, overwrite: true);
                }

                installed.Add((current, backup));
                InstallFile(path => entry.ExtractToFile(path, overwrite: true), current);
            });
        }
        catch (Exception ex)
        {
            RollBack(installed);
            throw new ArchiveVerificationException(
                $"Update not installed: could not install '{current.SanitizeForLog()}'. If it is locked by another process (for example IIS), stop the site or application pool and retry. The files already installed were rolled back where possible. ({ex.Message.SanitizeForLog()})",
                ex);
        }
    }

    private static void InstallFile(Action<string> write, string destination)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);

        try
        {
            write(destination);
        }
        catch (IOException)
        {
            var temp = $"{destination}.tmp";
            write(temp);
            File.Replace(temp, destination, $"{destination}.bak", ignoreMetadataErrors: true);
        }
    }

    private static void RollBack(List<(string Destination, string? Backup)> installed) =>
        Enumerable.Reverse(installed).ToList().ForEach(file =>
        {
            try
            {
                if (file.Backup is null)
                {
                    File.Delete(file.Destination);
                }
                else
                {
                    InstallFile(path => File.Copy(file.Backup, path, overwrite: true), file.Destination);
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                Trace.WriteLine($"Unable to roll back {file.Destination.SanitizeForLog()}: {ex.Message.SanitizeForLog()}");
            }
        });
}
