#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.AccessControl;
using System.Security.Principal;

namespace PingCastle.ADWS
{
    internal class WindowsFileConnection : IFileConnection
    {
        private readonly WindowsIdentity? _identity;

        public WindowsFileConnection(NetworkCredential? credential, string server)
        {
            if (credential != null)
            {
                var identityProvider = ServiceProviderAccessor.GetServiceSafe<IIdentityProvider>();
                if (identityProvider != null)
                {
                    _identity = identityProvider.GetWindowsIdentityForUser(credential, server);
                }
            }
        }

        /// <summary>
        /// Wraps an action with impersonation if credentials were provided, otherwise executes directly.
        /// </summary>
        public void RunImpersonatedIfNeeded(Action action)
        {
            if (_identity != null)
            {
                WindowsIdentity.RunImpersonated(_identity.AccessToken, action);
            }
            else
            {
                action();
            }
        }

        /// <summary>
        /// Wraps a function with impersonation if credentials were provided, otherwise executes directly.
        /// </summary>
        public T RunImpersonatedIfNeeded<T>(Func<T> func)
        {
            if (_identity != null)
            {
                return WindowsIdentity.RunImpersonated(_identity.AccessToken, func);
            }

            return func();
        }

        public bool IsDirectory(string path)
        {
            return RunImpersonatedIfNeeded(() =>
                (File.GetAttributes(path) & FileAttributes.Directory) == FileAttributes.Directory);
        }

        public DirectorySecurity GetDirectorySecurity(string path)
        {
            return RunImpersonatedIfNeeded(() => new DirectoryInfo(path).GetAccessControl());
        }

        public FileSecurity GetFileSecurity(string path)
        {
            return RunImpersonatedIfNeeded(() => new FileInfo(path).GetAccessControl());
        }

        public IEnumerable<string> GetSubDirectories(string path)
        {
            return RunImpersonatedIfNeeded(() =>
            {
                DirectoryInfo di = new DirectoryInfo(path);
                DirectoryInfo[] allDirectories = di.GetDirectories();
                var o = new List<string>();
                foreach (var d in allDirectories)
                {
                    o.Add(d.FullName);
                }
                return o;
            });
        }

        public bool FileExists(string path)
        {
            return RunImpersonatedIfNeeded(() => File.Exists(path));
        }

        public bool DirectoryExists(string path)
        {
            return RunImpersonatedIfNeeded(() => new DirectoryInfo(path).Exists);
        }

        private void Unmount()
        {
            if (_identity != null)
            {
                _identity.Dispose();
            }
        }


        #region IDispose
        public void Dispose()
        {
            // If this function is being called the user wants to release the
            // resources. lets call the Dispose which will do this for us.
            Dispose(true);

            // Now since we have done the cleanup already there is nothing left
            // for the Finalizer to do. So lets tell the GC not to call it later.
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing == true)
            {
                //someone want the deterministic release of all resources
                //Let us release all the managed resources
                Unmount();
            }
            else
            {
                // Do nothing, no one asked a dispose, the object went out of
                // scope and finalized is called so lets next round of GC 
                // release these resources
            }

            // Release the unmanaged resource in any case as they will not be 
            // released by GC
        }


        ~WindowsFileConnection()
        {
            // The object went out of scope and finalized is called
            // Lets call dispose in to release unmanaged resources 
            // the managed resources will anyways be released when GC 
            // runs the next time.
            Dispose(false);
        }
        #endregion IDispose

        public Stream GetFileStream(string path)
        {
            return RunImpersonatedIfNeeded(() => new FileStream(path, FileMode.Open, FileAccess.Read));
        }

        public string GetShortName(string path)
        {
            if (string.IsNullOrEmpty(path))
            {
                return string.Empty;
            }

            var p = path.Split('\\');
            return p[^1];
        }

        public DateTime GetLastWriteTime(string path)
        {
            return RunImpersonatedIfNeeded(() =>
            {
                FileInfo fi = new FileInfo(path);
                return fi.LastWriteTime;
            });
        }

        public string PathCombine(string path1, string path2)
        {
            return Path.Combine(path1, path2);
        }

        public List<string> GetAllSubDirectories(string path)
        {
            return RunImpersonatedIfNeeded(() =>
                new List<string>(Directory.GetDirectories(path, "*", SearchOption.AllDirectories)));
        }

        public List<string> GetAllSubFiles(string path)
        {
            return RunImpersonatedIfNeeded(() =>
                new List<string>(Directory.GetFiles(path, "*.*", SearchOption.AllDirectories)));
        }

        public void ThreadInitialization()
        {
            // Note: In .NET Framework, this maintained impersonation context across threads.
            // .NET 8 does not support thread-level impersonation (no Impersonate() method).
            // Impersonation now must be scoped to individual operations via RunImpersonatedIfNeeded().

            // TODO: Remove this method and chase down all calls to ensure impersonation is handled correctly.
        }
    }
}
