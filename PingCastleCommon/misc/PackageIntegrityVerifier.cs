namespace PingCastle.misc;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.Versioning;
using Netwrix.AuthenticodeVerification;
using PingCastleCommon;
using PingCastleCommon.Utility;


/// <summary>
/// Verifies the integrity of a downloaded update package before it is trusted.
/// </summary>
public static class PackageIntegrityVerifier
{
    /// <summary>
    /// Returns true when <paramref name="entry"/> must carry a valid PingCastle signature:
    /// .exe files and PingCastle*.dll files. Callers extracting the remaining entries must skip these,
    /// as <see cref="VerifyArchive"/> installs them from the verified copies.
    /// </summary>
    public static bool RequiresSignature(ZipArchiveEntry entry)
    {
        if (string.IsNullOrEmpty(entry.Name))
        {
            return false;
        }

        return entry.Name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
               (entry.Name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) &&
                entry.Name.StartsWith("PingCastle", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Verifies that every entry of the archive at <paramref name="zipFilePath"/> matching
    /// <see cref="RequiresSignature"/> carries a valid Authenticode signature. Entries are staged to a
    /// temporary directory and held under a verification lease; only when every entry passes are the
    /// leased files copied to <paramref name="targetDirectory"/>. Leases are released and the staging
    /// directory deleted afterwards.
    /// </summary>
    /// <param name="zipFilePath">Full path of the local archive to verify.</param>
    /// <param name="targetDirectory">Absolute install directory, or null to verify without installing.</param>
    /// <returns>True only when every executable entry passes signature verification and, when requested, is installed.</returns>
    [SupportedOSPlatform("windows")]
    public static bool VerifyArchive(string zipFilePath, string targetDirectory = null)
    {
        return VerifyArchive(zipFilePath, targetDirectory, out _);
    }

    /// <summary>
    /// As <see cref="VerifyArchive(string, string)"/>, additionally returning a human-readable reason on failure.
    /// </summary>
    /// <param name="zipFilePath">Full path of the local archive to verify.</param>
    /// <param name="targetDirectory">Absolute install directory, or null to verify without installing.</param>
    /// <param name="failureReason">Null on success; otherwise describes whether verification or installation failed.</param>
    /// <returns>True only when every executable entry passes signature verification and, when requested, is installed.</returns>
    [SupportedOSPlatform("windows")]
    public static bool VerifyArchive(string zipFilePath, string targetDirectory, out string failureReason)
    {
        failureReason = null;

        if (string.IsNullOrEmpty(zipFilePath) || !File.Exists(zipFilePath))
        {
            failureReason = "Package integrity check failed: archive not found " + zipFilePath.SanitizeForLog();
            Trace.WriteLine(failureReason);
            return false;
        }

        string stagingDirectory = Path.Combine(Path.GetTempPath(), "PingCastleVerify-" + Guid.NewGuid().ToString("N"));
        var verified = new List<(string EntryName, string StagedPath, VerifiedFileLease Lease)>();

        try
        {
            Directory.CreateDirectory(stagingDirectory);

            using (ZipArchive archive = ZipFile.OpenRead(zipFilePath))
            {
                if (!ExtractAndVerifyEntries(archive, stagingDirectory, verified))
                {
                    failureReason = "Package integrity check failed: an entry has an invalid or missing signature or a deceptive name.";
                    return false;
                }
            }

            if (targetDirectory != null)
            {
                var plan = verified
                    .Select(item => (item.StagedPath, Destination: FilesValidator.CheckPathTraversal(item.EntryName, targetDirectory)))
                    .ToList();

                InstallAll(plan, stagingDirectory);
            }

            return true;
        }
        catch (InstallFailedException ex)
        {
            failureReason = "Update not installed: could not replace '" + ex.Destination.SanitizeForLog() + "'. The file is probably locked by another process (e.g. IIS); stop the site or application pool and retry. A rollback of already installed files was attempted. (" + ex.InnerException.Message.SanitizeForLog() + ")";
            Trace.WriteLine(failureReason);
            return false;
        }
        catch (Exception ex) when (ex is ArgumentException || ex is NotSupportedException)
        {
            failureReason = "Package integrity check failed: invalid entry path in archive " + zipFilePath.SanitizeForLog() + " (" + ex.Message.SanitizeForLog() + ")";
            Trace.WriteLine(failureReason);
            return false;
        }
        catch (InvalidDataException ex)
        {
            failureReason = "Package integrity check failed: unreadable archive " + zipFilePath.SanitizeForLog() + " (" + ex.Message.SanitizeForLog() + ")";
            Trace.WriteLine(failureReason);
            return false;
        }
        catch (InvalidOperationException ex)
        {
            failureReason = "Package integrity check failed: invalid entry path in archive " + zipFilePath.SanitizeForLog() + " (" + ex.Message.SanitizeForLog() + ")";
            Trace.WriteLine(failureReason);
            return false;
        }
        catch (IOException ex)
        {
            failureReason = "Package integrity check failed: IO error for archive " + zipFilePath.SanitizeForLog() + " (" + ex.Message.SanitizeForLog() + ")";
            Trace.WriteLine(failureReason);
            return false;
        }
        catch (UnauthorizedAccessException ex)
        {
            failureReason = "Package integrity check failed: access denied for archive " + zipFilePath.SanitizeForLog() + " (" + ex.Message.SanitizeForLog() + ")";
            Trace.WriteLine(failureReason);
            return false;
        }
        finally
        {
            foreach (var item in verified)
            {
                item.Lease.Dispose();
            }

            try
            {
                if (Directory.Exists(stagingDirectory))
                {
                    Directory.Delete(stagingDirectory, true);
                }
            }
            catch (IOException ex)
            {
                Trace.WriteLine("Unable to remove the package verification staging directory: " + ex.Message.SanitizeForLog());
            }
            catch (UnauthorizedAccessException ex)
            {
                Trace.WriteLine("Unable to remove the package verification staging directory: " + ex.Message.SanitizeForLog());
            }
        }
    }

    /// <summary>
    /// Returns true when the entry name could resolve on Windows to a different file than its extension
    /// suggests: an alternate data stream (':') or a trailing dot or space, both of which would let an
    /// unsigned file escape <see cref="RequiresSignature"/> yet still land on a signed file name.
    /// </summary>
    private static bool HasDeceptiveName(ZipArchiveEntry entry)
    {
        return entry.FullName.Contains(':') ||
               (entry.Name.Length > 0 && (entry.Name.EndsWith('.') || entry.Name.EndsWith(' ')));
    }

    /// <summary>
    /// Extracts and verifies all entries from the archive that require a signature.
    /// </summary>
    /// <param name="archive">The ZIP archive to process.</param>
    /// <param name="stagingDirectory">Directory to stage extracted files.</param>
    /// <param name="verified">Collection to populate with verified entries and their leases.</param>
    /// <returns>True if all required entries pass verification; false if any entry fails.</returns>
    private static bool ExtractAndVerifyEntries(
        ZipArchive archive,
        string stagingDirectory,
        List<(string EntryName, string StagedPath, VerifiedFileLease Lease)> verified)
    {
        foreach (ZipArchiveEntry entry in archive.Entries)
        {
            if (HasDeceptiveName(entry))
            {
                Trace.WriteLine("Package integrity check failed: deceptive entry name " + entry.FullName.SanitizeForLog());
                return false;
            }

            // Reject entries that escape the target before anything is installed, including entries that are not staged.
            FilesValidator.CheckPathTraversal(entry.FullName, stagingDirectory);

            if (!RequiresSignature(entry))
            {
                continue;
            }

            // Entry names are untrusted: staging by file name only, into a unique flat
            // directory, keeps an entry from escaping the staging directory.
            string stagedPath = Path.Combine(stagingDirectory, verified.Count + "_" + Path.GetFileName(entry.Name));

            entry.ExtractToFile(stagedPath, true);

            // We use BestOnlineEffort as the revocation check can fail if the CRL is not reachable, but we still want to verify the signature.
            //  This is because some customers run air-gapped environments where the CRL is not reachable, but the signature is still valid.
            //  This gives us the best balance between security and usability, as we still want to verify the signature, but we don't want to fail the installation if the CRL is not reachable.
            if (!WindowsTrustChecker.TryVerifyPingCastleSignature(stagedPath, RevocationPolicy.OnlineBestEffort, out VerifiedFileLease lease))
            {
                Trace.WriteLine("Package integrity check failed: invalid or missing signature for " + entry.FullName.SanitizeForLog());
                return false;
            }

            verified.Add((entry.FullName, stagedPath, lease));
        }

        return true;
    }

    private static void InstallAll(List<(string StagedPath, string Destination)> plan, string stagingDirectory)
    {
        var installed = new List<(string Destination, string Backup)>();
        string current = null;

        try
        {
            foreach (var item in plan)
            {
                current = item.Destination;
                string backup = null;
                if (File.Exists(item.Destination))
                {
                    backup = Path.Combine(stagingDirectory, "backup_" + installed.Count);
                    File.Copy(item.Destination, backup, true);
                }

                installed.Add((item.Destination, backup));
                InstallVerifiedFile(item.StagedPath, item.Destination);
            }
        }
        catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
        {
            RollBack(installed);
            throw new InstallFailedException(current, ex);
        }
        catch (Exception)
        {
            RollBack(installed);
            throw;
        }
    }

    private sealed class InstallFailedException : Exception
    {
        public InstallFailedException(string destination, Exception inner)
            : base("Unable to install " + destination, inner)
        {
            Destination = destination;
        }

        public string Destination { get; }
    }

    private static void RollBack(List<(string Destination, string Backup)> installed)
    {
        for (int i = installed.Count - 1; i >= 0; i--)
        {
            try
            {
                if (installed[i].Backup != null)
                {
                    InstallVerifiedFile(installed[i].Backup, installed[i].Destination);
                }
                else if (File.Exists(installed[i].Destination))
                {
                    File.Delete(installed[i].Destination);
                }
            }
            catch (IOException ex)
            {
                Trace.WriteLine("Unable to roll back " + installed[i].Destination.SanitizeForLog() + ": " + ex.Message.SanitizeForLog());
            }
            catch (UnauthorizedAccessException ex)
            {
                Trace.WriteLine("Unable to roll back " + installed[i].Destination.SanitizeForLog() + ": " + ex.Message.SanitizeForLog());
            }
        }
    }

    private static void InstallVerifiedFile(string stagedPath, string destination)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);

        try
        {
            File.Copy(stagedPath, destination, true);
        }
        catch (IOException)
        {
            // The destination is in use (e.g. the running updater): File.Replace can swap an in-use
            // file by moving it to a backup name.
            string tempPath = destination + ".tmp";
            File.Copy(stagedPath, tempPath, true);
            File.Replace(tempPath, destination, destination + ".bak", true);
        }
    }
}