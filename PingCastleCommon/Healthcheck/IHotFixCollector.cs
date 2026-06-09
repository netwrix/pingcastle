// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.misc;
using System.Threading;

namespace PingCastle.Healthcheck
{
    /// <summary>
    /// Interface for collecting installed hotfixes from remote computers.
    /// </summary>
    public interface IHotFixCollector
    {
        /// <summary>
        /// Retrieves installed hotfixes from a remote computer using CIM with WMI fallback.
        /// Hotfix retrieval requires privileged mode access to remote systems.
        /// </summary>
        /// <param name="hostName">Target computer hostname or IP address</param>
        /// <param name="isPrivilegedMode">Whether privileged mode is active. Hotfix collection requires high privileges.</param>
        /// <param name="cancellationToken">Token used to cancel the operation if the per-host deadline fires.</param>
        /// <returns>A <see cref="HotfixQueryResult"/> containing query status and any discovered KB numbers</returns>
        HotfixQueryResult GetInstalledHotfixes(string hostName, bool isPrivilegedMode = true, CancellationToken cancellationToken = default);
    }
}
