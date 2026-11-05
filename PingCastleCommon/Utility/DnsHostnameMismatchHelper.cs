// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
using System;

namespace PingCastleCommon.Utility
{
    public static class DnsHostnameMismatchHelper
    {
        public static bool IsMismatch(string samAccountName, string dnsHostName)
        {
            if (string.IsNullOrEmpty(dnsHostName))
            {
                return false;
            }

            if (string.IsNullOrEmpty(samAccountName))
            {
                return false;
            }

            const int NetBiosNameMaxLength = 15;

            var dotIndex = dnsHostName.IndexOf('.');
            var hostLabel = dotIndex >= 0 ? dnsHostName.Substring(0, dotIndex) : dnsHostName;

            var accountName = samAccountName.TrimEnd('$');

            if (accountName.Length == NetBiosNameMaxLength && hostLabel.Length > NetBiosNameMaxLength)
            {
                return !hostLabel.StartsWith(accountName, StringComparison.OrdinalIgnoreCase);
            }

            return !string.Equals(hostLabel, accountName, StringComparison.OrdinalIgnoreCase);
        }
    }
}
