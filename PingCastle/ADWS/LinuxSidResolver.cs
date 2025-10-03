using Microsoft.Win32.SafeHandles;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace PingCastle.ADWS
{
    public static class LinuxSidResolverSettings
    {
        public static string LogLevel { get; set; }
    }

    internal class LinuxSidResolver : IDisposable
    {
        const int SECURITY_MAX_SID_SIZE = 68;

        internal const string SmbLibrary = "libPingCastlesmb";

        [DllImport(SmbLibrary, CharSet = CharSet.Ansi)]
        static internal extern IntPtr _talloc_stackframe(string context);

        [DllImport(SmbLibrary, CharSet = CharSet.Ansi)]
        static internal extern void _talloc_free(IntPtr context);

        [DllImport(SmbLibrary, CharSet = CharSet.Ansi)]
        internal static extern void cli_shutdown(IntPtr cli);

        [DllImport(SmbLibrary, CharSet = CharSet.Ansi)]
        internal static extern IntPtr user_auth_info_init(IntPtr mem_ctx);

        [DllImport(SmbLibrary, CharSet = CharSet.Ansi)]
        internal static extern void set_cmdline_auth_info_domain(IntPtr auth_info, string domain);

        [DllImport(SmbLibrary, CharSet = CharSet.Ansi)]
        internal static extern void set_cmdline_auth_info_password(IntPtr auth_info, string password);

        [DllImport(SmbLibrary, CharSet = CharSet.Ansi)]
        internal static extern void set_cmdline_auth_info_username(IntPtr auth_info, string password);

        [DllImport(SmbLibrary, CharSet = CharSet.Ansi)]
        internal static extern int cli_full_connection(out SambaConnectionHandle output_cli,
                 string my_name,
                 string dest_host,
                IntPtr dest_ss, int port,
                 string service, string service_type,
                 string user, string domain,
                 string password, int flags,
                 int signing_state);

        [DllImport(SmbLibrary, CharSet = CharSet.Ansi)]
        internal static extern void ndr_table_lsarpc();

        internal delegate void RPCTable();

        [DllImport(SmbLibrary, CharSet = CharSet.Ansi)]
        internal static extern int cli_rpc_pipe_open_noauth(SambaConnectionHandle cli,
                  RPCTable table,
                  out IntPtr presult);

        internal struct policy_handle
        {
            public UInt32 handle_type;
            public Guid uuid;
        }

        [DllImport(SmbLibrary, CharSet = CharSet.Ansi)]
        internal static extern int rpccli_lsa_open_policy(IntPtr cli,
                IntPtr mem_ctx,
                bool sec_qos, uint des_access,
                ref policy_handle pol);

        [DllImport(SmbLibrary, CharSet = CharSet.Ansi)]
        internal static extern int rpccli_lsa_lookup_sids(IntPtr cli,
                IntPtr mem_ctx,
                ref policy_handle pol,
                int num_sids,
                byte[] sids,
                out SambaTallocHandle pdomains,
                out SambaTallocHandle pnames,
                out SambaTallocHandle ptypes);

        [DllImport(SmbLibrary, CharSet = CharSet.Ansi)]
        internal static extern int rpccli_lsa_lookup_names(IntPtr cli,
                IntPtr mem_ctx,
                ref policy_handle pol,
                int num_sids,
                string[] names,
                out SambaTallocHandle pdomains,
                int level,
                out SambaTallocHandle sids,
                out SambaTallocHandle ptypes);

        [DllImport(SmbLibrary, CharSet = CharSet.Ansi)]
        internal static extern void lp_set_cmdline(string i, string j);

        IntPtr memoryContext;
        static object lockobject = new object();
        //in
        NetworkCredential credential;
        string remoteserver;
        // lsa connections state
        SambaConnectionHandle connectionHandle;
        IntPtr rpcHandle;
        policy_handle policy = new policy_handle();

        public LinuxSidResolver(NetworkCredential credential, string remoteserver)
        {
            if (credential == null)
                throw new NotImplementedException("Credential required");
            memoryContext = _talloc_stackframe("PingCastle");
            this.credential = credential;
            this.remoteserver = remoteserver;
        }

        private IntPtr BuildAuthInfo()
        {
            Trace.WriteLine(@"BuildAuthInfo");
            var auth = user_auth_info_init(memoryContext);
            set_cmdline_auth_info_domain(auth, credential.Domain);
            set_cmdline_auth_info_username(auth, credential.UserName);
            set_cmdline_auth_info_password(auth, credential.Password);
            return auth;
        }


        private int ConnectWithFull()
        {
            Trace.WriteLine(@"Before ConnectoWithFull");
            return cli_full_connection(out connectionHandle, "PingCastle", remoteserver,
                IntPtr.Zero, 0,
                "IPC$", "IPC",
                credential.UserName,
                credential.Domain,
                credential.Password,
                0,
                -2);
        }

        private void ConnectToLsa()
        {
            Trace.WriteLine(@"ConnectToLsa Init");
            if (!string.IsNullOrEmpty(LinuxSidResolverSettings.LogLevel))
            {
                lp_set_cmdline("log level", LinuxSidResolverSettings.LogLevel);
            }
            lp_set_cmdline("client ipc signing", "required");
            var r = ConnectWithFull();
            if (r != 0)
            {
                throw new Win32Exception(r, "Unable to ConnectWithFull");
            }
            r = cli_rpc_pipe_open_noauth(connectionHandle, ndr_table_lsarpc, out rpcHandle);
            if (r != 0)
            {
                throw new Win32Exception(r, "Unable to cli_rpc_pipe_open_noauth");
            }
            r = rpccli_lsa_open_policy(rpcHandle, memoryContext, true, (uint)(1L << 25), ref policy);
            if (r != 0)
            {
                throw new Win32Exception(r, "Unable to rpccli_lsa_open_policy");
            }
            Trace.WriteLine(@"ConnectToLsa OK");
        }

        private void DisconnectFromLsa()
        {

            connectionHandle.Close();
        }

        public string ConvertSIDToName(string sidstring, out string referencedDomain)
        {
            lock (lockobject)
            {
                if (rpcHandle == IntPtr.Zero)
                    ConnectToLsa();

                referencedDomain = null;
                var sids = new byte[SECURITY_MAX_SID_SIZE * 1];
                var sid = new SecurityIdentifier(sidstring);

                sid.GetBinaryForm(sids, 1 * 0);

                SambaTallocHandle domainsIntPtr;
                SambaTallocHandle namesIntPtr;
                SambaTallocHandle typesIntPtr;
                var status = rpccli_lsa_lookup_sids(rpcHandle, memoryContext, ref policy, 1, sids,
                         out domainsIntPtr, out namesIntPtr, out typesIntPtr);
                if (status != 0)
                {
                    Trace.WriteLine(@"Error " + status + " when translating " + sidstring + " on " + remoteserver);
                    return sidstring;
                }
                var domains1 = Marshal.ReadIntPtr(domainsIntPtr.DangerousGetHandle());
                referencedDomain = Marshal.PtrToStringAnsi(domains1);

                var names1 = Marshal.ReadIntPtr(namesIntPtr.DangerousGetHandle());
                var name = Marshal.PtrToStringAnsi(names1);

                domainsIntPtr.Close();
                namesIntPtr.Close();
                typesIntPtr.Close();

                if (String.IsNullOrEmpty(referencedDomain))
                    return name;
                else
                    return referencedDomain + "\\" + name;
            }
        }

        public SecurityIdentifier ConvertNameToSid(string nameToResolve)
        {
            lock (lockobject)
            {
                if (rpcHandle == IntPtr.Zero)
                    ConnectToLsa();
                SambaTallocHandle domainsIntPtr;
                SambaTallocHandle sidsIntPtr;
                SambaTallocHandle typesIntPtr;

                var status = rpccli_lsa_lookup_names(rpcHandle, memoryContext, ref policy, 1, new string[] { nameToResolve },
                             out domainsIntPtr, 1, out sidsIntPtr, out typesIntPtr);
                if (status != 0)
                {
                    Trace.WriteLine(@"Error " + status + " when translating " + nameToResolve + " on " + remoteserver);
                    return null;
                }
                var domains1 = Marshal.ReadIntPtr(domainsIntPtr.DangerousGetHandle());
                var referencedDomain = Marshal.PtrToStringAnsi(domains1);
                var sid = new SecurityIdentifier(sidsIntPtr.DangerousGetHandle());
                sidsIntPtr.Close();
                domainsIntPtr.Close();
                typesIntPtr.Close();
                return sid;
            }
        }

        public void Dispose()
        {
            if (rpcHandle != IntPtr.Zero)
                DisconnectFromLsa();
        }
    }

    internal class SambaTallocHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SambaTallocHandle() : base(true)
        {
        }

        public SambaTallocHandle(IntPtr handle)
            : base(true)
        {
            SetHandle(handle);
        }

        protected override bool ReleaseHandle()
        {
            LinuxSidResolver._talloc_free(this.handle);
            return true;
        }
    }

    internal class SambaConnectionHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        
        public SambaConnectionHandle()
            : base(true)
        {
        }

        public SambaConnectionHandle(IntPtr handle)
            : base(true)
        {
            SetHandle(handle);
        }

        protected override bool ReleaseHandle()
        {
            LinuxSidResolver.cli_shutdown(this.handle);
            return true;
        }
    }
}
