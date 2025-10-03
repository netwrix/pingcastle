namespace PingCastle.misc
{
    using System;
    using System.Security.Cryptography;
    using System.Text;
    using PingCastleCommon.Utility;

    public static class Base64UrlEncoder
    {
        /// <summary>
        /// Encodes the specified byte array to Base64
        /// </summary>
        /// <param name="byteArray">The byte array to encode.</param>
        /// <returns>The encoded array as a base 64 string.</returns>
        public static string EncodeToUrlSafeBase64(byte[] byteArray) =>
            byteArray == null ? null : Convert.ToBase64String(byteArray).Split('=')[0].Replace('+', '-').Replace('/', '_');

        /// <summary>
        /// Creates a Base64, Url encoded SHA256 hash of the given input
        /// </summary>
        /// <param name="input">The string to encode</param>
        /// <returns>A string with the encoded output.</returns>
        public static string CreateBase64UrlEncodedSha256Hash(string input) =>
            !input.IsNullOrEmpty() ? EncodeToUrlSafeBase64(CreateSha256HashBytes(input)) : null;

        private static byte[] CreateSha256HashBytes(string input)
        {
            using SHA256Cng sha = new SHA256Cng();
            return input.IsNullOrWhiteSpace() ? null : sha.ComputeHash(Encoding.UTF8.GetBytes(input));
        }
    }
}