//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System.Net;

namespace PingCastle.ADWS
{
    /// <summary>
    /// Factory for creating AD connections with the specified parameters.
    /// </summary>
    public interface IADConnectionFactory
    {
        /// <summary>
        /// Creates an AD connection with the specified parameters.
        /// The returned connection implements IDisposable and should be disposed after use.
        /// </summary>
        /// <param name="server">The AD server hostname or IP address</param>
        /// <param name="port">The LDAP port (typically 389 for LDAP or 636 for LDAPS)</param>
        /// <param name="credential">Network credentials for the connection</param>
        /// <param name="identityProvider">Instance for connection to use to retrieve identity and convert SIDs</param>
        /// <returns>An IADWebService instance ready for use</returns>
        IADWebService CreateConnection(string server, int port, NetworkCredential credential, IIdentityProvider identityProvider, IWindowsNativeMethods nativeMethods);
    }
}
