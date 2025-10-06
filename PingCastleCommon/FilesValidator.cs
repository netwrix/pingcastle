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
            if (!fullFilePath.StartsWith(baseDirectory, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("Invalid file path detected. The file must be within the allowed directory.");
            }

            return fullFilePath;
        }

        public static string CheckPathTraversalAbsolute(string fileName)
        {
            if (fileName.IndexOfAny(Path.GetInvalidPathChars()) >= 0)
            {
                throw new InvalidOperationException("The file path contains invalid characters.");
            }

            return Path.GetFullPath(fileName);
        }

        public static void CheckAbsolutePath(string path)
        {
            if (!IsAbsolutePath(path))
            {
                throw new InvalidOperationException("The directory path is not an absolute path.");
            }
        }

        static bool IsAbsolutePath(string path)
        {
            // Check if the path is rooted and if it is not just a root like "\"
            return Path.IsPathRooted(path) && !string.IsNullOrEmpty(Path.GetPathRoot(path)) && Path.GetPathRoot(path) != Path.DirectorySeparatorChar.ToString();
        }
    }
}
