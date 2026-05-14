using System;
using System.Collections.Generic;
using System.Linq;
using PingCastleCommon.Utility;

namespace PingCastleAutoUpdater
{
    internal class Release
    {
        public string name { get; set; }
        public bool prerelease { get; set; }
        public DateTime published_at { get; set; }
        public List<Asset> assets { get; set; }
    }

    internal class Asset
    {
        public string name { get; set; }
        public int size { get; set; }
        public string browser_download_url { get; set; }
    }

    internal class ParseResult
    {
        public bool Success { get; set; }
        public string Error { get; set; }
        public bool ForceDownload { get; set; }
        public bool Preview { get; set; }
        public bool DryRun { get; set; }
        public bool ShowHelp { get; set; }
        public int WaitForDays { get; set; }
        public string ApiUrl { get; set; } = "https://api.github.com/repos/netwrix/pingcastle/releases";
    }

    internal static class UpdaterLogic
    {
        internal static bool IsValidReleaseUrl(string url)
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out Uri uri))
                return false;

            return (uri.Scheme == "http" || uri.Scheme == "https") && !string.IsNullOrEmpty(uri.Host);
        }

        internal static Version ParseReleaseVersion(string releaseName)
        {
            if (string.IsNullOrEmpty(releaseName))
            {
                throw new ArgumentException("Release name is empty");
            }

            var parts = releaseName.Split(' ');
            for (int i = parts.Length - 1; i >= 0; i--)
            {
                var part = parts[i];
                if (Version.TryParse(part, out Version version))
                {
                    return version;
                }
            }

            if (Version.TryParse(releaseName, out Version directVersion))
            {
                return directVersion;
            }

            throw new ArgumentException($"Could not parse version from release name: {releaseName}");
        }

        internal static bool IsUpdateRequired(string currentVersion, string latestVersion, bool forceDownload)
        {
            if (forceDownload)
            {
                return true;
            }

            if (string.IsNullOrEmpty(currentVersion))
            {
                return true;
            }

            try
            {
                var current = new Version(currentVersion);
                var latest = ParseReleaseVersion(latestVersion);
                return latest > current;
            }
            catch
            {
                // Fail safe: proceed with update when version comparison is uncertain
                return true;
            }
        }

        internal static Release FilterAndSortReleases(IEnumerable<Release> releases, bool includePrerelease, int waitForDays)
        {
            if (releases == null)
            {
                return null;
            }

            IEnumerable<Release> filtered = releases;

            if (waitForDays > 0)
            {
                filtered = filtered.Where(r => r.published_at.AddDays(waitForDays) < DateTime.Now);
            }

            if (!includePrerelease)
            {
                filtered = filtered.Where(r => r.prerelease == false);
            }

            filtered = filtered.OrderByDescending(i => i.published_at);

            return filtered.FirstOrDefault();
        }

        internal static ParseResult ParseArguments(string[] args)
        {
            var result = new ParseResult { Success = true };

            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "--api-url":
                        if (i + 1 >= args.Length)
                        {
                            return new ParseResult { Success = false, Error = "argument for --api-url is mandatory" };
                        }

                        var customUrl = args[++i];
                        if (!IsValidReleaseUrl(customUrl))
                        {
                            return new ParseResult { Success = false, Error = "Invalid API URL. Only HTTP and HTTPS URLs are allowed." };
                        }

                        result.ApiUrl = customUrl;
                        break;
                    case "--force-download":
                        result.ForceDownload = true;
                        break;
                    case "--help":
                        result.ShowHelp = true;
                        return result;
                    case "--use-preview":
                        result.Preview = true;
                        break;
                    case "--dry-run":
                        result.DryRun = true;
                        break;
                    case "--wait-for-days":
                        if (i + 1 >= args.Length)
                        {
                            return new ParseResult { Success = false, Error = "argument for --wait-for-days is mandatory" };
                        }

                        if (!int.TryParse(args[++i], out int days))
                        {
                            return new ParseResult { Success = false, Error = "argument for --wait-for-days is not a valid value (typically: 30)" };
                        }

                        result.WaitForDays = days;
                        break;
                    default:
                        return new ParseResult { Success = false, Error = "unknown argument: " + args[i].SanitizeForLog() };
                }
            }

            return result;
        }
    }
}
