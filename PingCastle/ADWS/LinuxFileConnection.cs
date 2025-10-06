using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

namespace PingCastle.ADWS
{
    public class LinuxFileConnection : IFileConnection
    {
        public LinuxFileConnection(NetworkCredential credential, ADDomainInfo domainInfo)
        {
            Credential = credential;
            this.domainInfo = domainInfo;
            Init();
        }
        
        static NetworkCredential Credential;
        ADDomainInfo domainInfo;
        object lockThread = new object();

        IntPtr context;
        private void Init()
        {
            smbc_init(AuthenticationCallback, 0);
            context = smbc_new_context();
            if (context == IntPtr.Zero)
            {
                throw new ApplicationException("Unable to run smbc_new_context");
            }
            var smbContext = smbc_init_context(context);
            if (smbContext == IntPtr.Zero)
            {
                throw new ApplicationException("Unable to run smbc_init_context");
            }
            context = smbContext;
        }

        static void AuthenticationCallback(string srv,
                                      string shr,
                                      IntPtr workgroup, int wglen,
                                      IntPtr username, int unlen,
                                      IntPtr password, int pwlen)
        {
            Trace.WriteLine("Authentication callback with " + srv + " " + shr);
            SetString(workgroup, Credential.Domain, wglen);
            SetString(username, Credential.UserName, unlen);
            SetString(password, Credential.Password, pwlen);
        }

        private void ShutDown()
        {
            if (context != IntPtr.Zero)
            {
                smbc_free_context(context, 1);
                context = IntPtr.Zero;
            }
        }

        string ConvertPath(string path)
        {
            if (path.StartsWith("smb://", StringComparison.OrdinalIgnoreCase))
                return path;
            if (!path.StartsWith("\\\\", StringComparison.OrdinalIgnoreCase))
            {
                throw new ApplicationException("Unable to parse the path 1");
            }
            if (domainInfo != null && path.StartsWith("\\\\" + domainInfo.DomainName + "\\"))
            {
                path = "\\\\" + domainInfo.DnsHostName + "\\" + path.Substring(domainInfo.DomainName.Length + 3);
            }
            int slash = path.IndexOf('\\', 2);
            if (slash < 0)
                throw new ApplicationException("Unable to parse the path 2");

            return "smb://" + path.Substring(2, slash - 2) + "//" + path.Substring(slash + 1).Replace('\\', '/');
        }

        public bool IsDirectory(string path)
        {
            lock (lockThread)
            {
                Trace.WriteLine("Linux IsDirectory " + path);
                int fd = smbc_opendir(ConvertPath(path));
                if (fd < 0)
                {
                    return false;
                }
                smbc_closedir(fd);
                return true;
            }
        }

        public System.Security.AccessControl.DirectorySecurity GetDirectorySecurity(string path)
        {
            lock (lockThread)
            {
                Trace.WriteLine("Linux GetDirectorySecurity " + path);
                var ds = new DirectorySecurity();
                ds.SetOwner(new SecurityIdentifier(GetAttr(path, "system.nt_sec_desc.owner")));
                ds.SetGroup(new SecurityIdentifier(GetAttr(path, "system.nt_sec_desc.group")));
                var acls = GetAttr(path, "system.nt_sec_desc.acl.*");
                foreach (var acl in acls.Split(','))
                {
                    var part = acl.Split(':');
                    var part2 = part[1].Split('/');
                    var type = int.Parse(part2[0]);
                    var flags = int.Parse(part2[1]);
                    var access_mask = Convert.ToUInt32(part2[2], 16);
                    ds.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(part[0]), (FileSystemRights)access_mask, (AccessControlType)type));
                }
                return ds;
            }
        }

        public System.Security.AccessControl.FileSecurity GetFileSecurity(string path)
        {
            lock (lockThread)
            {
                Trace.WriteLine("Linux GetFileSecurity " + path);
                var fs = new FileSecurity();
                fs.SetOwner(new SecurityIdentifier(GetAttr(path, "system.nt_sec_desc.owner")));
                fs.SetGroup(new SecurityIdentifier(GetAttr(path, "system.nt_sec_desc.group")));
                var acls = GetAttr(path, "system.nt_sec_desc.acl.*");
                foreach (var acl in acls.Split(','))
                {
                    var part = acl.Split(':');
                    var part2 = part[1].Split('/');
                    var type = int.Parse(part2[0]);
                    var flags = int.Parse(part2[1]);
                    var access_mask = Convert.ToUInt32(part2[2], 16);
                    fs.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(part[0]), (FileSystemRights)access_mask, (AccessControlType)type));
                }
                return fs;
            }
        }

        string GetAttr(string path, string property)
        {
            var size = smbc_getxattr(ConvertPath(path), property, IntPtr.Zero, 0);
            if (size < 0)
            {
                throw new LinuxFileConnectionException(size, path);
            }
            var output = Marshal.AllocHGlobal(size);
            try
            {
                var ret = smbc_getxattr(ConvertPath(path), property, output, size);
                if (ret < 0)
                {
                    throw new LinuxFileConnectionException(ret, path);
                }
                return Marshal.PtrToStringAnsi(output);
            }
            finally
            {
                Marshal.FreeHGlobal(output);
            }
        }

        public IEnumerable<string> GetSubDirectories(string path)
        {
            lock (lockThread)
            {
                return GetSubNodes(path, smbc_entity.SMBC_DIR);
            }
        }
        
        List<string> GetSubNodes(string path, smbc_entity type)
        {
            var output = new List<string>();
            Trace.WriteLine("Linux GetSubNodes " + path);
            int fd = smbc_opendir(ConvertPath(path));
            if (fd < 0)
            {
                Trace.WriteLine("Unable to open " + path + " (" + fd + ")");
                if (fd != -1)
                {
                    throw new LinuxFileConnectionException(fd, path);
                }
                return output;
            }
            IntPtr cursor;
            while((cursor = smbc_readdir(fd)) != IntPtr.Zero)
            {
                var b = new IntPtr(cursor.ToInt64() + Marshal.OffsetOf(typeof(smbc_dirent), "name").ToInt64());
                var dirent = (smbc_dirent) Marshal.PtrToStructure(cursor, typeof(smbc_dirent));
                var name = Marshal.PtrToStringAnsi(b, dirent.namelen);
                if (name == "." || name == "..")
                    continue;

                if (dirent.smbc_type == type)
                {
                    if (path.EndsWith("\\"))
                        output.Add(path + name);
                    else
                        output.Add(path + "\\" + name);
                }
            }
            smbc_closedir(fd);
            return output;
        }

        public bool FileExists(string path)
        {
            lock (lockThread)
            {
                Trace.WriteLine("Linux FileExists " + path);
                int fd = smbc_open(ConvertPath(path), 0, 0);
                if (fd < 0)
                {
                    return false;
                }
                smbc_closedir(fd);
                return true;
            }
        }

        public bool DirectoryExists(string path)
        {
            lock (lockThread)
            {
                Trace.WriteLine("Linux DirectoryExists " + path);
                int fd = smbc_opendir(ConvertPath(path));
                if (fd < 0)
                {
                    return false;
                }
                smbc_closedir(fd);
                return true;
            }
        }


        public System.IO.Stream GetFileStream(string path)
        {
            lock(lockThread)
            {
                Trace.WriteLine("Linux GetFileStream " + path);
                var fd = smbc_open(ConvertPath(path), 0, 0);
                if (fd < 0)
                {
                    throw new LinuxFileConnectionException(fd, path);
                }
                return new LinuxFileStream(fd);
            }
        }


        public string GetShortName(string path)
        {
            var t = path.Split('\\');
            return t[t.Length - 1];
        }


        public DateTime GetLastWriteTime(string path)
        {
            lock (lockThread)
            {
                IntPtr ptr = Marshal.AllocHGlobal(120);
                try
                {
                    var ret = smbc_stat(ConvertPath(path), ptr);
                    if (ret < 0)
                    {
                        throw new LinuxFileConnectionException(ret, path);
                    }
                    //Console.WriteLine(stat.st_mtime);
                    long i = Marshal.ReadInt64(ptr, 88);
                    return new System.DateTime(1970, 1, 1).AddSeconds(i);
                }
                finally
                {
                    Marshal.FreeHGlobal(ptr);
                }
            }
        }


        public string PathCombine(string path1, string path2)
        {
            if (path1.EndsWith("\\"))
                return path1 + path2;
            return path1 + "\\" + path2;
        }


        public List<string> GetAllSubDirectories(string path)
        {
            lock (lockThread)
            {
                var output = new List<string>();
                GetSubDirectoriesRecursive(path, output);
                return output;
            }
        }

        void GetSubDirectoriesRecursive(string path, List<string> output)
        {
            foreach (var dir in GetSubNodes(path, smbc_entity.SMBC_DIR))
            {
                output.Add(dir);
                GetSubDirectoriesRecursive(dir, output);
            }
        }

        public List<string> GetAllSubFiles(string path)
        {
            lock (lockThread)
            {
                var output = new List<string>();
                GetSubFilesRecursive(path, output);
                return output;
            }
        }

        void GetSubFilesRecursive(string path, List<string> output)
        {
            foreach (var dir in GetSubNodes(path, smbc_entity.SMBC_DIR))
            {
                output.AddRange(GetSubNodes(path, smbc_entity.SMBC_FILE));
                GetSubDirectoriesRecursive(dir, output);
            }
        }

        static private void SetString(IntPtr dest, string str, int maxLen)
        {
            // include null string terminator
            byte[] buffer = Encoding.ASCII.GetBytes(str + "\0");
            if (buffer.Length >= maxLen) return; // buffer is not big enough

            Marshal.Copy(buffer, 0, dest, buffer.Length);
        }

        public void ThreadInitialization()
        {
        }

        #region pinvoke
        internal const string SmbLibrary = "libPingCastlesmb";
        
        [DllImport(SmbLibrary, CharSet = CharSet.Ansi)]
        static extern IntPtr smbc_new_context();

        [DllImport(SmbLibrary, CharSet = CharSet.Ansi)]
        static extern IntPtr smbc_init_context(IntPtr context);

        [DllImport(SmbLibrary, CharSet = CharSet.Ansi)]
        static extern int smbc_free_context(IntPtr context, int shutdown_ctx);

        delegate void AuthenticationCallbackDelegate(string srv,
                                      string shr,
                                      IntPtr wg, int wglen,
                                      IntPtr un, int unlen,
                                      IntPtr pw, int pwlen);

        [DllImport(SmbLibrary, CharSet = CharSet.Ansi)]
        static extern int smbc_init(AuthenticationCallbackDelegate fn, int debug);
        
        [DllImport(SmbLibrary, CharSet = CharSet.Ansi)]
        static extern int smbc_open(string furl, int flags, int mode);
        
        [DllImport(SmbLibrary, CharSet = CharSet.Ansi)]
        static extern int smbc_read(int fd, IntPtr buf, IntPtr bufsize);

        [DllImport(SmbLibrary, CharSet = CharSet.Ansi)]
        static extern int smbc_close(int fd);

        [DllImport(SmbLibrary, CharSet = CharSet.Ansi)]
        static extern int smbc_opendir(string durl);
        
        [DllImport(SmbLibrary, CharSet = CharSet.Ansi)]
        static extern int smbc_closedir(int dh);

        enum smbc_entity 
        {
            SMBC_WORKGROUP=1,
	        SMBC_SERVER=2,
	        SMBC_FILE_SHARE=3,
	        SMBC_PRINTER_SHARE=4,
	        SMBC_COMMS_SHARE=5,
	        SMBC_IPC_SHARE=6,
	        SMBC_DIR=7,
	        SMBC_FILE=8,
	        SMBC_LINK=9
        }
        [StructLayout(LayoutKind.Sequential, CharSet= CharSet.Ansi)]
        struct smbc_dirent
        {
	        /** Type of entity.
             */
            public smbc_entity smbc_type;
	        /** Length of this smbc_dirent in bytes
	         */
            public uint dirlen;
	        /** The length of the comment string in bytes (does not include
	         *  null terminator)
	         */
            public uint commentlen;
	        /** Points to the null terminated comment string
	         */
            public IntPtr comment;
	        /** The length of the name string in bytes (does not include
	         *  null terminator)
	         */
            public int namelen;
	        /** Points to the null terminated name string
	         */
            public char name;
        };

        [DllImport(SmbLibrary, CharSet = CharSet.Ansi)]
        static extern IntPtr smbc_readdir(int dh);

        [DllImport(SmbLibrary, CharSet = CharSet.Ansi)]
        static extern int smbc_stat(string url, IntPtr stat);

        [DllImport(SmbLibrary, CharSet = CharSet.Ansi)]
        static extern int smbc_getxattr(string path, string property, IntPtr value, int size);

        #endregion pinvoke

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
                ShutDown();
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


        ~LinuxFileConnection()
        {
            // The object went out of scope and finalized is called
            // Lets call dispose in to release unmanaged resources 
            // the managed resources will anyways be released when GC 
            // runs the next time.
            Dispose(false);
        }
        #endregion IDispose


    }

    internal class LinuxFileStream : Stream
    {
        int descriptor;
        public LinuxFileStream(int fd) : base()
        {
            descriptor = fd;
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            IntPtr mem = Marshal.AllocHGlobal(count);
            var result = smbc_read(descriptor, mem, count);
            Marshal.Copy(mem, buffer, offset, count);
            Marshal.FreeHGlobal(mem);
            return result;
        }

        private void CloseTheHandle()
        {
            if (descriptor >= 0)
            {
                smbc_close(descriptor);
                descriptor = 0;
            }
        }

        public override void Close()
        {
            CloseTheHandle();
            base.Close();
        }

        [DllImport(LinuxFileConnection.SmbLibrary, CharSet = CharSet.Ansi)]
        static extern int smbc_read(int fd, IntPtr buf, int bufsize);

        [DllImport(LinuxFileConnection.SmbLibrary, CharSet = CharSet.Ansi)]
        static extern int smbc_close(int fd);


        public override bool CanRead
        {
            get { return true; }
        }

        public override bool CanSeek
        {
            get { return false; }
        }

        public override bool CanWrite
        {
            get { return false; }
        }

        public override void Flush()
        {
            throw new NotImplementedException();
        }

        public override long Length
        {
            get { throw new NotImplementedException(); }
        }

        public override long Position
        {
            get
            {
                throw new NotImplementedException();
            }
            set
            {
                throw new NotImplementedException();
            }
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotImplementedException();
        }

        public override void SetLength(long value)
        {
            throw new NotImplementedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotImplementedException();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                CloseTheHandle();
            }
            base.Dispose(disposing);
        }
    }

    internal class LinuxFileConnectionException: Win32Exception
    {
        public LinuxFileConnectionException(int error, string file)
            : base(map_nt_error_from_unix(error), file + " : " + error + " " + map_nt_error_from_unix(error))
        {
        }

        [DllImport(LinuxFileConnection.SmbLibrary, CharSet = CharSet.Ansi)]
        static extern int map_nt_error_from_unix(int z);
    }
}
