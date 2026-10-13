using System;
using System.IO;

namespace PingCastleCommon
{
    public static class FilesValidator
    {
        public static string CheckPathTraversal(string fileName, string path = null)
        {
            if (string.IsNullOrEmpty(path))
            {
                path = Directory.GetCurrentDirectory();
            }
            else
            {
                CheckAbsolutePath(path);
            }

            string baseDirectory = Path.GetFullPath(path);
            string fullFilePath = Path.GetFullPath(Path.Combine(path, fileName));

            // Check for invalid path characters
            if (fileName.IndexOfAny(Path.GetInvalidPathChars()) >= 0)
            {
                throw new InvalidOperationException("The file path contains invalid characters.");
            }

            // Validate that the file path is within the base directory
            string normalizedBase = baseDirectory.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            string normalizedFull = fullFilePath.TrimEnd(Path.DirectorySeparatorChar);
            if (!normalizedFull.StartsWith(normalizedBase, StringComparison.OrdinalIgnoreCase) && !normalizedFull.Equals(normalizedBase.TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("Invalid file path detected. The file must be within the allowed directory.");
            }

            return fullFilePath;
        }

        public static void CheckAbsolutePath(string path)
        {
            if (!IsAbsolutePath(path))
            {
                throw new InvalidOperationException("The directory path is not an absolute path.");
            }
        }

        private static bool IsAbsolutePath(string path)
        {
            // A bare separator is a fully qualified root on Linux ("/") but only a
            // drive-relative root on Windows ("\"), so only reject it on Windows.
            bool isBareRoot = Path.GetPathRoot(path) == Path.DirectorySeparatorChar.ToString();
            return Path.IsPathRooted(path) && !string.IsNullOrEmpty(Path.GetPathRoot(path)) && (!isBareRoot || Path.DirectorySeparatorChar == '/');
        }
    }
}
