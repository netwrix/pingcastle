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
    }
}