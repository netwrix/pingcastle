#nullable enable

// Positional record parameters become PascalCase properties; SA1313 does not apply to them.
#pragma warning disable SA1313

namespace Netwrix.ArchiveVerification;

using System.IO.Compression;
using System.Linq;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using NJsonSchema;
using NJsonSchema.Infrastructure;
using static Netwrix.ArchiveVerification.ArchiveVerificationException;
using PingCastle.misc;
using PingCastleCommon;
using PingCastleCommon.Utility;
using RevocationPolicy = Netwrix.AuthenticodeVerification.RevocationPolicy;

/// <summary>
/// A zip verified against the manifest signed by us, kept open (and so locked against changes) until
/// disposed. The constructor checks, in this order: the manifest and its signature (size limited, signed by
/// an approved key, valid against the JSON schema, which also rejects deceptive file names); that the zip
/// holds as many files as the manifest; then, file by file, the name and size against the manifest, a path
/// that stays inside the directory it is extracted to and the SHA256 (read once without writing it anywhere);
/// and last the Authenticode signature of the files that must be signed. Each file is verified only
/// once, because the open zip cannot change: callers read or extract <see cref="Entries"/> themselves and
/// must check the destination path. Any problem in the constructor throws
/// <see cref="ArchiveVerificationException"/> from its single try/catch. Entries are valid until the
/// archive is disposed. Not thread-safe.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class VerifiedArchive : IDisposable
{
    private const string ManifestName = "manifest.json";
    private const string SignatureName = $"{ManifestName}.sig";

    // Our limits on the two files read into memory, so a package cannot make us read a huge entry.
    // An RSA-4096 signature in base64 is about 700 bytes.
    private const long MaxManifestBytes = 16L * ByteSize.MiB;
    private const long MaxSignatureBytes = 4 * ByteSize.KiB;
    private const string ProbeRoot = @"C:\package\";

    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    // Lazy, so a failure to load the schema surfaces inside the constructor, not as a TypeInitializationException.
    private static readonly Lazy<JsonSchema> ManifestSchema = new(LoadManifestSchema);

    // The public keys approved to sign the manifest (RSA, PKCS#1 v1.5, SHA256).
    private static readonly RSAParameters[] ApprovedKeys =
    {
        new()
        {
            Exponent = Convert.FromBase64String("AQAB"),
            Modulus = Convert.FromBase64String(
            "tuAS/36obI7D+TEDudIC7pc1Edc0S9xM8Gtl77CPvzqVGZXktKtw+fdyEpew9GmKD4aA25Nt9In0eSrNg+SOW0ExlFstVcLM9SdnfqoNaN9fk68EDupoE4RVth6uWz0RLlzwVcoInYP0FZ6R225ESuR7CTz+kHi7lhNA6I3giElLJAKZ7JPeUcjZa20o8IqqO56Dm2Ln869ZVMcXdpPYQq5QAtmkge6MG7D0yl11UAoUdya4flALqYcyoqnCpN9pFT6W7IMq0cZpos9+b6wKbJtd75enHdsERYuwiGgoQEBg2WvTgt7UVsRO1q0KYqrCqjjSJzc9M3bLT3yRLYjknTYRFLgMRZtDdI/1W7pVqd2H9ntU+rgKnYRJxwg2i9fAovnM2KrXE08Kqmm+E+BEryA7KMlKE/c/gG/endUQUg2Xu14e+7IhltZMFKCrCpdgbpVSAtCDtstysNNLg1c67wi6VCXZvmq/53bb1a31Cp2m0gexsmZ6kKCUe2biJLL3muzc5WTknN0+IWWJ1WDfBAUQoN63HQkAR3uPGcCESgpRYzBRWB5z56kBlUD6Rjlaf33Ht7V+shNjdbaEFADpnbPC3OrL8TFUWCQ1Zi0pnpIpb2jAiVjWK8tsBU/TCoZ2O3av61/sDkX3ILRq5a9hkBH83JqX0uQgywN/BBYOMIU="),
        },
    };

    private readonly ZipArchive archive;

    /// <summary>
    /// Verifies the zip at <paramref name="zipPath"/>.
    /// </summary>
    /// <param name="zipPath">The zip to verify.</param>
    public VerifiedArchive(string zipPath)
    {
        ZipArchive? opened = null;
        try
        {
            opened = ZipFile.OpenRead(zipPath);
            var manifest = ReadManifest(opened);
            var payload = opened.Entries.Where(e => e.Name.Length > 0 && e.FullName is not (ManifestName or SignatureName)).ToList();

            VerifyPayload(payload, manifest);
            Entries = payload;
            archive = opened;
        }
        catch (Exception ex)
        {
            opened?.Dispose();
            var error = ex is not ArchiveVerificationException
                ? new ArchiveVerificationException($"Archive could not be verified: {zipPath.SanitizeForLog()} ({ex.Message.SanitizeForLog()})", ex)
                : ex;
            throw error;
        }
    }

    /// <summary>
    /// Gets the verified files: exactly those in the manifest, without the manifest and its signature.
    /// </summary>
    public IReadOnlyList<ZipArchiveEntry> Entries { get; }

    /// <summary>
    /// Returns true when the file must carry a trusted Authenticode signature: every .exe, and every .dll
    /// whose name starts with PingCastle.
    /// </summary>
    public static bool RequiresSignature(string relativePath)
    {
        var name = Path.GetFileName(relativePath);
        return name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
               || (name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
                   && name.StartsWith("PingCastle", StringComparison.OrdinalIgnoreCase));
    }

    public void Dispose() => archive.Dispose();

    // Reads exactly the declared length, which is checked against the limit first, so a huge entry
    // can never be read into memory.
    private static byte[] ReadEntry(ZipArchive archive, string name, long maxBytes)
    {
        var entry = archive.GetEntry(name)
                    ?? throw new ArchiveVerificationException($"Archive has no signed manifest: {name} is required.");
        Ensure(entry.Length <= maxBytes, $"{name} is too large: {entry.Length} bytes, the limit is {maxBytes}");

        using var stream = entry.Open();
        var bytes = new byte[entry.Length];
        stream.ReadExactly(bytes);
        return bytes;
    }

    private static JsonSchema LoadManifestSchema()
    {
        using var stream = typeof(VerifiedArchive).Assembly.GetManifestResourceStream("manifest.schema.json")!;
        using var reader = new StreamReader(stream);
        return JsonSchemaSerialization.FromJson<JsonSchema>(reader.ReadToEnd(), JsonSchema.CreateJsonSerializerContractResolver(SchemaType.JsonSchema));
    }

    private static bool IsSignedWith(RSAParameters key, byte[] data, byte[] signature)
    {
        using var rsa = RSA.Create(key);
        return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    private static List<ManifestEntry> ReadManifest(ZipArchive archive)
    {
        var manifest = ReadEntry(archive, ManifestName, MaxManifestBytes);
        var signatureText = Encoding.UTF8.GetString(ReadEntry(archive, SignatureName, MaxSignatureBytes)).Trim();
        var signature = Ensure(() => Convert.FromBase64String(signatureText), "Manifest signature file is not valid base64");
        Ensure(ApprovedKeys.Any(key => IsSignedWith(key, manifest, signature)), "Manifest signature is not valid for any approved key.");

        var json = Encoding.UTF8.GetString(manifest);
        var schema = Ensure(() => ManifestSchema.Value, "Manifest schema could not be loaded");
        var errors = Ensure(() => schema.Validate(json), "Manifest is not valid JSON");
        Ensure(errors.Count == 0, $"Manifest does not match its schema: {errors.FirstOrDefault()?.ToString().SanitizeForLog()}");

        return JsonNode.Parse(json)!["files"].Deserialize<List<ManifestEntry>>(JsonOptions)!;
    }

    // Verifies every file once, so that any later read from the locked zip is safe: the files are exactly those
    // in the manifest with the listed sizes (checked before each file is read, so nothing larger than the signed
    // manifest allows is ever read), their paths stay inside the extraction directory, they have the listed
    // SHA256, and the files that must be signed have a trusted signature.
    private static void VerifyPayload(List<ZipArchiveEntry> payload, List<ManifestEntry> manifest)
    {
        Ensure(payload.Count == manifest.Count, $"The archive has {payload.Count} files, the manifest lists {manifest.Count}");

        payload.OrderBy(p => p.FullName, StringComparer.OrdinalIgnoreCase)
            .Zip(manifest.OrderBy(m => m.Path, StringComparer.OrdinalIgnoreCase), (entry, listed) => (Entry: VerifyFile(entry, listed), listed.Sha256))
            .Where(p => RequiresSignature(p.Entry.FullName))
            .ToList()
            .ForEach(p => CheckSignature(p.Entry, p.Sha256));
    }

    private static ZipArchiveEntry VerifyFile(ZipArchiveEntry entry, ManifestEntry listed)
    {
        Ensure(
            string.Equals(entry.FullName, listed.Path, StringComparison.OrdinalIgnoreCase) && entry.Length == listed.Size,
            $"The archive does not match the manifest, first difference: {$"{entry.FullName} (archive) / {listed.Path} (manifest)".SanitizeForLog()}");
        Ensure(() => FilesValidator.CheckPathTraversal(entry.FullName, ProbeRoot), $"Unsafe path {entry.FullName.SanitizeForLog()}");
        using var stream = entry.Open();
        Ensure(HasSha256(stream, listed.Sha256), $"SHA256 does not match the manifest for {entry.FullName.SanitizeForLog()}");
        return entry;
    }

    // Authenticode needs a path, so the file is extracted to a temporary file, which is deleted on leaving. The
    // file could be replaced between extraction and verification, so while the lease keeps the verified file
    // locked, it must still have the SHA256 listed in the manifest.
    private static void CheckSignature(ZipArchiveEntry entry, string sha256)
    {
        using var temp = new TempFile();
        entry.ExtractToFile(temp.FullPath, overwrite: true);

        var trusted = WindowsTrustChecker.TryVerifyPingCastleSignature(temp.FullPath, RevocationPolicy.OnlineBestEffort, out var lease);
        using (lease)
        {
            Ensure(trusted && HasSha256(temp.FullPath, sha256), $"Signature is missing or not trusted: {entry.FullName.SanitizeForLog()}");
        }
    }

    private static bool HasSha256(string path, string sha256)
    {
        using var stream = File.OpenRead(path);
        return HasSha256(stream, sha256);
    }

    private static bool HasSha256(Stream stream, string sha256) =>
        string.Equals(Convert.ToHexString(SHA256.HashData(stream)), sha256, StringComparison.OrdinalIgnoreCase);

    private sealed record ManifestEntry(string Path, long Size, string Sha256);
}
