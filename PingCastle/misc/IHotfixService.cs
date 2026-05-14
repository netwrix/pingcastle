using PingCastle.UserInterface;
using System.Threading;

namespace PingCastle.misc
{
    /// <summary>
    /// Interface for hotfix detection services.
    /// Provides methods to retrieve installed hotfixes from remote computers.
    /// </summary>
    public interface IHotfixService
    {
        /// <summary>
        /// Retrieves installed hotfixes from a remote computer.
        /// </summary>
        /// <param name="hostName">Target computer hostname or IP address.</param>
        /// <param name="ui">User interface for displaying messages.</param>
        /// <param name="cancellationToken">Token used to cancel the operation cooperatively.</param>
        /// <returns>A <see cref="HotfixQueryResult"/> containing the query outcome and any discovered KB numbers.</returns>
        HotfixQueryResult TryGetInstalledHotfixes(string hostName, IUserInterface ui, CancellationToken cancellationToken = default);
    }
}
