namespace PingCastleCommon.Utility;

using System.Net;
using System.Text.RegularExpressions;

public static class NetworkHelper
{
    /// <summary>
    /// Validates hostname to prevent command injection, script injection, and other security issues.
    /// Accepts valid DNS hostnames, NetBIOS names, IPv4, and IPv6 addresses.
    /// </summary>
    /// <param name="hostName">Hostname to validate</param>
    /// <returns>True if hostname is valid and safe to use in WMI operations</returns>
    public static bool IsValidHostName(string hostName)
    {
        if (string.IsNullOrWhiteSpace(hostName))
        {
            return false;
        }

        // Check length - DNS hostnames limited to 253 characters
        if (hostName.Length > 253)
        {
            return false;
        }

        // Try to parse as IP address first
        if (IPAddress.TryParse(hostName, out IPAddress ip))
        {
            // Valid IPv4 or IPv6 address
            return true;
        }

        // Validate as DNS hostname or NetBIOS name
        var hostnameRegex = new Regex(@"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$", RegexOptions.Compiled);
        return hostnameRegex.IsMatch(hostName);
    }
}