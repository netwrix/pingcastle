namespace Netwrix.AuthenticodeVerification.Interop;

internal static class PathValidator
{
    public static bool ValidateAndIsUnc(string filePath)
    {
        if (filePath is null)
        {
            throw new ArgumentNullException(nameof(filePath));
        }

        if (string.IsNullOrWhiteSpace(filePath) || !IsFullyQualified(filePath))
        {
            throw new ArgumentException(
                "The candidate path must be fully qualified and absolute.",
                nameof(filePath));
        }

        _ = Path.GetFullPath(filePath);
        return IsUnc(filePath);
    }

    public static bool IsUnc(string path)
    {
        if (path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)
            || path.StartsWith(@"\\.\UNC\", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return path.StartsWith(@"\\", StringComparison.Ordinal)
            && !path.StartsWith(@"\\?\", StringComparison.Ordinal)
            && !path.StartsWith(@"\\.\", StringComparison.Ordinal);
    }

    private static bool IsFullyQualified(string path)
    {
#if NETFRAMEWORK
        if (path.StartsWith(@"\\", StringComparison.Ordinal))
        {
            return true;
        }

        return path.Length >= 3
            && IsAsciiLetter(path[0])
            && path[1] == ':'
            && IsDirectorySeparator(path[2]);
#else
        return Path.IsPathFullyQualified(path);
#endif
    }

#if NETFRAMEWORK
    private static bool IsAsciiLetter(char value)
    {
        return (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z');
    }

    private static bool IsDirectorySeparator(char value)
    {
        return value == Path.DirectorySeparatorChar || value == Path.AltDirectorySeparatorChar;
    }
#endif
}
