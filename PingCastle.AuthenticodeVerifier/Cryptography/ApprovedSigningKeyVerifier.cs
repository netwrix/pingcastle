using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Netwrix.AuthenticodeVerification.Cryptography;

internal static class ApprovedSigningKeyVerifier
{
#if NETFRAMEWORK
    /// <summary>
    /// Approved Netwrix RSA public keys represented by their complete modulus and exponent.
    /// See <see href="https://learn.microsoft.com/dotnet/api/system.security.cryptography.rsaparameters"><c>RSAParameters</c></see>.
    /// </summary>
    private static readonly ApprovedRsaKey[] ApprovedKeys =
    {
        new(
            Convert.FromBase64String(
                "tkhJNRfxUv4mTCXugItiFEws4R9fQJapjplfEjOKym77GZX1nKoK1w7mEuFOurzuMkDT2EFbE9Xh4/hrC29pQDEl5pXvrnRefew2b7YVi4lcDpABbfi/Y52Rpc9Tn+8d4ARZYB0kmh1lJPQLug08PYNrkLu/GqDOaE3OO7U/ntc7XnSihGSaFfnXjpqigwAXYKLvSpgF1HkM+qzpo2ederj/WBjHHpf9dqHzvo00dw3zdwZ1N5OuS2LBthxyiiglg0jFVzuMuRfKAXcP9JKcnqwJ5QfDm2e2lLPv9m6s8ZSvVR66Q+niuGjAV5blD3qOtrWhkVzqYMl7IENUxv1pVy/w9zCQtlDqx2PW/pxTzT72YB6PzNuPYMJldJHUX13z+h7xrrKIcCFfYQ6EenhHYILDoBx/HRzCF8sl/QBRH+PjLT6uQkk15nd/9CWBHVN8ZrlsrLcwDoXvhZTeRH3Gia/C0DM1Ak2yIPP4ymjJQAfISMXZSUQlgCcREtG58UR7mXk+cB5Oe5+2QibwWIoqgt/4NN8kOSCjFkJevpieJzGbEiqZm3OC4LPdgKirLXHECSJcyjMQ5Fth3K1qnNjFCECL45r/p4gYKCHoL0w1GWdlaQYOcrW1SzGzwukTJZyoxfM4LsT59fdmPg/vpzQxidH3EPUwmSraeUGG6xxNX1M="),
            Convert.FromBase64String("AQAB")),
    };
#else
    /// <summary>
    /// The SHA-256 digest length in bytes.
    /// See <see href="https://learn.microsoft.com/dotnet/api/system.security.cryptography.sha256.hashdata"><c>SHA256.HashData</c></see>.
    /// </summary>
    private const int Sha256DigestSizeInBytes = 32;

    /// <summary>
    /// Approved Netwrix SHA-256 SubjectPublicKeyInfo pins.  Hex matches the organisation's
    /// established representation; cryptographic comparison uses the decoded bytes.
    /// SubjectPublicKeyInfo is defined by
    /// <see href="https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.7">RFC 5280 section 4.1.2.7</see>.
    /// </summary>
    private static readonly byte[][] ApprovedSpkiSha256Hashes =
    {
        Convert.FromHexString("C0CBAB8B2C41EAC332DA9B192A1E5B20E3D84E9E6E79EB2F835626303208046D"),
    };
#endif

    public static bool IsApproved(X509Certificate2 certificate)
    {
        if (certificate is null)
        {
            throw new ArgumentNullException(nameof(certificate));
        }

#if NETFRAMEWORK
        // .NET Framework identifies the complete RSA key by one modulus-and-exponent entry.
        using RSA? rsa = certificate.GetRSAPublicKey();
        if (rsa is null)
        {
            return false;
        }

        RSAParameters parameters = rsa.ExportParameters(includePrivateParameters: false);
        return MatchesRsaKey(parameters.Modulus, parameters.Exponent, ApprovedKeys);
#else
        // SPKI binds the algorithm identifier, parameters, and complete public-key value.
        // https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.7
        byte[] subjectPublicKeyInfo = certificate.PublicKey.ExportSubjectPublicKeyInfo();
        byte[] hash = SHA256.HashData(subjectPublicKeyInfo);
        return MatchesSpkiHash(hash, ApprovedSpkiSha256Hashes);
#endif
    }

#if NETFRAMEWORK
    internal static bool MatchesRsaKey(
        byte[]? modulus,
        byte[]? exponent,
        IReadOnlyList<ApprovedRsaKey> approvedKeys)
    {
        if (modulus is null
            || exponent is null
            || modulus.Length == 0
            || exponent.Length == 0
            || approvedKeys is null)
        {
            return false;
        }

        foreach (ApprovedRsaKey approvedKey in approvedKeys)
        {
            if (FixedTimeEquals(modulus, approvedKey.Modulus)
                && FixedTimeEquals(exponent, approvedKey.Exponent))
            {
                return true;
            }
        }

        return false;
    }
#else
    internal static bool MatchesSpkiHash(
        byte[]? candidateHash,
        IReadOnlyList<byte[]> approvedHashes)
    {
        if (candidateHash is null
            || candidateHash.Length != Sha256DigestSizeInBytes
            || approvedHashes is null)
        {
            return false;
        }

        foreach (byte[] approvedHash in approvedHashes)
        {
            if (approvedHash.Length == Sha256DigestSizeInBytes
                && CryptographicOperations.FixedTimeEquals(candidateHash, approvedHash))
            {
                return true;
            }
        }

        return false;
    }
#endif

#if NETFRAMEWORK
    private static bool FixedTimeEquals(byte[] left, byte[] right)
    {
        if (left.Length != right.Length)
        {
            return false;
        }

        int difference = 0;
        for (int index = 0; index < left.Length; index++)
        {
            difference |= left[index] ^ right[index];
        }

        return difference == 0;
    }
#endif
}

#if NETFRAMEWORK
internal sealed class ApprovedRsaKey
{
    public ApprovedRsaKey(byte[] modulus, byte[] exponent)
    {
        Modulus = modulus ?? throw new ArgumentNullException(nameof(modulus));
        Exponent = exponent ?? throw new ArgumentNullException(nameof(exponent));
    }

    public byte[] Modulus { get; }

    public byte[] Exponent { get; }
}
#endif
