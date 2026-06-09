using System.Linq;
using System.Text;

namespace PingCastleCommon.Utility
{
    /// <summary>
    /// Useful extension methods for strings.
    /// </summary>
    public static class StringExtensions
    {
        /// <summary>Indicates whether the specified string is <see langword="null" /> or an empty string ("").</summary>
        /// <param name="value">The string to test.</param>
        /// <returns>
        /// <see langword="true" /> if the <paramref name="value" /> parameter is <see langword="null" /> or an empty string (""); otherwise, <see langword="false" />.</returns>
        public static bool IsNullOrEmpty(this string value)
        {
            return string.IsNullOrEmpty(value);
        }

        /// <summary>Indicates whether a specified string is <see langword="null" />, empty, or consists only of white-space characters.</summary>
        /// <param name="value">The string to test.</param>
        /// <returns>
        /// <see langword="true" /> if the <paramref name="value" /> parameter is <see langword="null" /> or <see cref="F:System.String.Empty" />, or if <paramref name="value" /> consists exclusively of white-space characters.</returns>
        public static bool IsNullOrWhiteSpace(this string value)
        {
            return string.IsNullOrWhiteSpace(value);
        }

        /// <summary>Indicates whether the first character of a string is a vowel.</summary>
        /// <param name="value">The string to test.</param>
        /// <returns>
        /// <see langword="true" /> if the string is not empty and starts with a vowel (a, e, i, o, u, A, E, I, O, U); otherwise, <see langword="false" />.</returns>
        public static bool StartsWithVowel(this string value)
        {
            return !string.IsNullOrEmpty(value) && "aeiouAEIOU".Contains(value[0]);
        }

        /// <summary>Gets the appropriate indefinite article (a or an) for the string based on its first character.</summary>
        /// <param name="value">The string to get the article for.</param>
        /// <returns>"an" if the string starts with a vowel; "a" otherwise.</returns>
        public static string GetArticle(this string value)
        {
            return value.StartsWithVowel() ? "an" : "a";
        }

        /// <summary>
        /// Sanitizes string for safe logging by escaping control characters that could enable log forging attacks.
        /// Escapes ALL control characters (including newlines, carriage returns, tabs) to visible representations.
        /// </summary>
        /// <param name="value">The string to sanitize.</param>
        /// <param name="maxLength">Maximum length for truncation (default 200 for typical log fields).</param>
        /// <returns>Sanitized string safe for logging, or empty string if input is null.</returns>
        public static string SanitizeForLog(this string value, int maxLength = 200)
        {
            if (string.IsNullOrEmpty(value))
                return string.Empty;

            // Truncate to prevent log flooding/DoS
            var truncated = value.Length > maxLength
                ? value.Substring(0, maxLength) + "..."
                : value;

            // Escape control characters to prevent log injection while preserving evidence of attacks
            var sb = new StringBuilder(truncated.Length * 2); // Extra capacity for escape sequences
            foreach (char c in truncated)
            {
                if (char.IsControl(c))
                {
                    // Show escaped form to detect log forging attempts
                    switch (c)
                    {
                        case '\n': sb.Append("\\n"); break;
                        case '\r': sb.Append("\\r"); break;
                        case '\t': sb.Append("\\t"); break;
                        default:
                            // For other control chars, use hex notation
                            sb.Append($"\\x{((int)c):X2}");
                            break;
                    }
                }
                else
                {
                    sb.Append(c);
                }
            }
            return sb.ToString();
        }
    }
}