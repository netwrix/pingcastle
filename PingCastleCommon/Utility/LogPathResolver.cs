#nullable enable
using System;
using System.IO;

namespace PingCastleCommon.Utility
{
    /// <summary>
    /// Resolves the configured log directory for a service, encoding the relative-versus-absolute rule
    /// shared by every service that honours the <c>Logging:LogFilePath</c> setting.
    /// </summary>
    public static class LogPathResolver
    {
        /// <summary>
        /// The path used when no log file path has been configured. Relative, so each service resolves it
        /// against its own base directory.
        /// </summary>
        public const string DefaultRelativePath = "logs";

        /// <summary>Indicates whether the configured path is rooted, in which case every service shares it.</summary>
        /// <param name="configuredPath">The configured log file path.</param>
        /// <returns>
        /// <see langword="true" /> if <paramref name="configuredPath" /> is rooted; otherwise, <see langword="false" />.</returns>
        public static bool IsAbsolute(string? configuredPath)
        {
            if (string.IsNullOrWhiteSpace(configuredPath))
            {
                return false;
            }

            return Path.IsPathRooted(configuredPath);
        }

        /// <summary>Resolves the configured path to an absolute log directory.</summary>
        /// <param name="configuredPath">The configured log file path. Blank falls back to <see cref="DefaultRelativePath" />.</param>
        /// <param name="serviceBaseDirectory">The base directory a relative path is resolved against.</param>
        /// <returns>The absolute log directory.</returns>
        public static string Resolve(string? configuredPath, string serviceBaseDirectory)
        {
            var path = string.IsNullOrWhiteSpace(configuredPath) ? DefaultRelativePath : configuredPath;

            if (Path.IsPathRooted(path))
            {
                return Path.GetFullPath(path);
            }

            return Path.GetFullPath(Path.Combine(serviceBaseDirectory, path));
        }

        /// <summary>
        /// Indicates whether the configured path is permitted, applying the same rules as the Settings UI:
        /// no directory traversal sequences and no UNC paths.
        /// </summary>
        /// <param name="configuredPath">The configured log file path.</param>
        /// <param name="reason">When the path is not permitted, the reason it was rejected; otherwise, <see langword="null" />.</param>
        /// <returns>
        /// <see langword="true" /> if the path is permitted; otherwise, <see langword="false" />.</returns>
        public static bool IsPermitted(string? configuredPath, out string? reason)
        {
            reason = null;

            if (string.IsNullOrEmpty(configuredPath))
            {
                return true;
            }

            var normalised = configuredPath.Replace('\\', '/');
            if (normalised.Contains("../") || normalised.Contains("..\\") || normalised == "..")
            {
                reason = "Log file path must not contain directory traversal sequences.";
                return false;
            }

            if (configuredPath.StartsWith(@"\\", StringComparison.Ordinal) || configuredPath.StartsWith("//", StringComparison.Ordinal))
            {
                reason = "Log file path must be a local path. UNC paths are not permitted.";
                return false;
            }

            return true;
        }
    }
}
