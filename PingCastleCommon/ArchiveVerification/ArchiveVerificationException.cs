#nullable enable

namespace Netwrix.ArchiveVerification;

using PingCastleCommon.Utility;

/// <summary>
/// Any failure while verifying or installing an archive. It is the only exception type callers need to catch.
/// </summary>
public sealed class ArchiveVerificationException : Exception
{
    public ArchiveVerificationException(string message)
        : base(message)
    {
    }

    public ArchiveVerificationException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    public static void Ensure(bool condition, string message)
    {
        if (!condition)
        {
            throw new ArchiveVerificationException(message);
        }
    }

    // Runs a check and returns its result; whatever the check throws is rewritten into the message.
    public static T Ensure<T>(Func<T> check, string message)
    {
        try
        {
            return check();
        }
        catch (Exception ex) when (ex is not ArchiveVerificationException)
        {
            throw new ArchiveVerificationException($"{message}: {ex.Message.SanitizeForLog()}", ex);
        }
    }
}
