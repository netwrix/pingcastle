using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace PingCastle.ADWS
{
    public interface IFileConnection : IDisposable
    {
        bool IsDirectory(string path);
        DirectorySecurity GetDirectorySecurity(string path);
        FileSecurity GetFileSecurity(string path);
        IEnumerable<string> GetSubDirectories(string path);
        bool FileExists(string path);
        bool DirectoryExists(string path);
        //StreamReader ReadFile(string path);
        string GetShortName(string path);
        Stream GetFileStream(string path);
        DateTime GetLastWriteTime(string path);
        string PathCombine(string path1, string path2);
        List<string> GetAllSubDirectories(string path);
        List<string> GetAllSubFiles(string path);

        void ThreadInitialization();
    }

    internal class WindowsFileConnection : IFileConnection
    {

        public bool IsDirectory(string path)
        {
            return (File.GetAttributes(path) & FileAttributes.Directory) == FileAttributes.Directory;
        }


        public DirectorySecurity GetDirectorySecurity(string path)
        {
            return Directory.GetAccessControl(path);
        }


        public FileSecurity GetFileSecurity(string path)
        {
            return File.GetAccessControl(path);
        }


        public IEnumerable<string> GetSubDirectories(string path)
        {
            DirectoryInfo di = new DirectoryInfo(path);
            DirectoryInfo[] AllDirectories = di.GetDirectories();
            var o = new List<string>();
            foreach(var d in AllDirectories)
            {
                o.Add(d.FullName);
            }
            return o;
        }


        public bool FileExists(string path)
        {
            return File.Exists(path);
        }

        public bool DirectoryExists(string path)
        {
            var directory = new DirectoryInfo(path);
            return directory.Exists;
        }

        WindowsIdentity identity;
        WindowsImpersonationContext context;

        public WindowsFileConnection(NetworkCredential credential, string server)
        {
            if (credential != null)
            {
                identity = GetWindowsIdentityForUser(credential, server);
                context = identity.Impersonate();
            }
        }

        private void Unmount()
        {
            if (context != null)
            {
                context.Undo();
                context.Dispose();
            }
            if (identity != null)
                identity.Dispose();
        }

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool LogonUser(string lpszUsername, string lpszDomain, string lpszPassword, int dwLogonType, int dwLogonProvider, ref IntPtr phToken);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        // logon types
        const int LOGON32_LOGON_NEW_CREDENTIALS = 9;

        // logon providers
        const int LOGON32_PROVIDER_DEFAULT = 0;

        public static WindowsIdentity GetWindowsIdentityForUser(NetworkCredential credential, string remoteserver)
        {
            IntPtr token = IntPtr.Zero;
            Trace.WriteLine("Preparing to login with login = " + credential.UserName + " remoteserver = " + remoteserver);
            var szDomain = credential.Domain;
            if (string.IsNullOrEmpty(szDomain))
            {
                if (!credential.UserName.Contains("@"))
                {
                    szDomain = remoteserver;
                }
            }

            bool isSuccess = LogonUser(credential.UserName, szDomain, credential.Password, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, ref token);
            if (!isSuccess)
            {
                throw new Win32Exception();
            }
            var output = new WindowsIdentity(token);
            CloseHandle(token);
            return output;
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
            return new FileStream(path, FileMode.Open, FileAccess.Read);
        }


        public string GetShortName(string path)
        {
            if (string.IsNullOrEmpty(path))
                return string.Empty;
            var p = path.Split('\\');
            return p[p.Length - 1];
        }


        public DateTime GetLastWriteTime(string path)
        {
            FileInfo fi = new FileInfo(path);
            return fi.LastWriteTime;
        }


        public string PathCombine(string path1, string path2)
        {
            return Path.Combine(path1, path2);
        }


        public List<string> GetAllSubDirectories(string path)
        {
            return new List<string>(Directory.GetDirectories(path, "*", SearchOption.AllDirectories));
        }

        public List<string> GetAllSubFiles(string path)
        {
            return new List<string>(Directory.GetFiles(path, "*.*", SearchOption.AllDirectories));
        }


        public void ThreadInitialization()
        {
            if (identity != null)
                identity.Impersonate();
        }
    }
}
