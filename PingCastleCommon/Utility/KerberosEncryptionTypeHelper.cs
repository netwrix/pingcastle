//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System.Collections.Generic;

namespace PingCastleCommon.Utility
{
    /// <summary>
    /// Resolves an msDS-SupportedEncryptionTypes bitmask into readable Kerberos algorithm names.
    /// See https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/6cfc7b50-11ed-4b4d-846d-6f08f0812919.
    /// </summary>
    public static class KerberosEncryptionTypeHelper
    {
        private const int DesCbcCrc = 1;
        private const int DesCbcMd5 = 2;
        private const int Rc4Hmac = 4;
        private const int Aes128 = 8;
        private const int Aes256 = 16;
        private const int Aes256SessionKey = 32;
        private const int KnownTypes = DesCbcCrc | DesCbcMd5 | Rc4Hmac | Aes128 | Aes256 | Aes256SessionKey;

        /// <summary>
        /// Builds a comma separated list of the algorithms declared by the bitmask.
        /// </summary>
        /// <param name="msDSSupportedEncryptionTypes">Raw msDS-SupportedEncryptionTypes value.</param>
        /// <returns>Readable algorithm names, or "Not set" when the attribute carries no value.</returns>
        public static string ToReadableString(int msDSSupportedEncryptionTypes)
        {
            if (msDSSupportedEncryptionTypes == 0)
            {
                return "Not set";
            }

            var algorithms = new List<string>();

            if ((msDSSupportedEncryptionTypes & DesCbcCrc) != 0)
            {
                algorithms.Add("DES-CBC-CRC");
            }

            if ((msDSSupportedEncryptionTypes & DesCbcMd5) != 0)
            {
                algorithms.Add("DES-CBC-MD5");
            }

            if ((msDSSupportedEncryptionTypes & Rc4Hmac) != 0)
            {
                algorithms.Add("RC4");
            }

            if ((msDSSupportedEncryptionTypes & Aes128) != 0)
            {
                algorithms.Add("AES128");
            }

            if ((msDSSupportedEncryptionTypes & Aes256) != 0)
            {
                algorithms.Add("AES256");
            }

            if ((msDSSupportedEncryptionTypes & Aes256SessionKey) != 0)
            {
                algorithms.Add("AES256-SK");
            }

            if ((msDSSupportedEncryptionTypes & ~KnownTypes) != 0)
            {
                algorithms.Add("Unrecognised");
            }

            return string.Join(", ", algorithms.ToArray());
        }
    }
}
