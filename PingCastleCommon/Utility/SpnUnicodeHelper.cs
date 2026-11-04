// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PingCastleCommon.Utility
{
    public static class SpnUnicodeHelper
    {
        private static readonly HashSet<int> InvisibleCodepoints = new HashSet<int>
        {
            0x200B, 0x200C, 0x200D, 0xFEFF, 0x200E, 0x200F,
            0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
            0xFFFC, 0xFFF9, 0xFFFA, 0xFFFB,
        };

        public static bool HasInvisibleChar(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return false;
            }

            return value.Any(c => InvisibleCodepoints.Contains(c));
        }

        public static string CleanValue(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return value;
            }

            if (!HasInvisibleChar(value))
            {
                return value;
            }

            var sb = new StringBuilder(value.Length);
            foreach (var c in value)
            {
                if (!InvisibleCodepoints.Contains(c))
                {
                    sb.Append(c);
                }
            }

            return sb.ToString();
        }

        public static string ToVisibleString(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return value;
            }

            var sb = new StringBuilder(value.Length);
            foreach (var c in value)
            {
                if (InvisibleCodepoints.Contains(c))
                {
                    sb.Append("[U+").Append(((int)c).ToString("X4")).Append(']');
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
