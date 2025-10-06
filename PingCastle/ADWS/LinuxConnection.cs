using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace PingCastle.ADWS
{
    [StructLayout(LayoutKind.Sequential)]
    public struct berval
    {
        public int bv_len;
        public IntPtr bv_val;

        public override string ToString()
        {
            if (bv_len == 0)
                return "Empty";
            if (bv_len < 5000)
            {
                byte[] managedArray = new byte[bv_len];
                Marshal.Copy(bv_val, managedArray, 0, bv_len);
                return BitConverter.ToString(managedArray);
            }
            return base.ToString();
        }

        public string GetString()
        {
            if (bv_val == IntPtr.Zero)
                return null;
            return Marshal.PtrToStringAuto(bv_val, bv_len);

        }

        public byte[] GetByteArray()
        {
            byte[] managedArray = new byte[bv_len];
            Marshal.Copy(bv_val, managedArray, 0, bv_len);
            return managedArray;
        }
    }

    internal class LinuxConnection : ADConnection
    {

        private ConnectionHandle connection { get; set; }

        public override void Enumerate(string distinguishedName, string filter, string[] properties, WorkOnReturnedObjectByADWS callback, string scope)
        {
            Trace.WriteLine("[" + DateTime.Now.ToLongTimeString() + "] Running ldap enumeration");
            Trace.WriteLine("BaseObject=" + scope);
            Trace.WriteLine("Filter=" + filter);
            Trace.WriteLine("distinguishedName=" + distinguishedName);
            Trace.WriteLine("scope=" + scope);

            IntPtr result;
            var r = ldap_search_s(connection, distinguishedName, StringToScope(scope), filter, properties, false, out result);
            if (r == -7)
            {
                // LDAP Error -7 (Bad search filter)
                // the filter contains a new attribute that the AD don't know - yet
                // just ignore it because the query will return nothing
                Trace.WriteLine("LDAP Error -7 (Bad search filter) - ignored");
                return;
            }
            if (r != 0)
                throw new LDAPException(r);
            try
            {
                var entry = ldap_count_entries(connection, result);
                var j = result;
                for (int i = 0; i < entry; i++)
                {
                    var data = new Dictionary<string, berval[]>();
                    foreach (var prop in properties)
                    {
                        data[prop] = GetValueBin(j, prop);
                    }
                    var aditem = ADItem.Create(data);
                    callback(aditem);
                    j = ldap_next_entry(connection, j);
                }
            }
            finally
            {
                ldap_memfree(result);
            }
        }

        LDAPScope StringToScope(string scope)
        {
            if (string.Equals(scope, "OneLevel", StringComparison.OrdinalIgnoreCase))
                return LDAPScope.LDAP_SCOPE_ONELEVEL;
            if (string.Equals(scope, "Base", StringComparison.OrdinalIgnoreCase))
                return LDAPScope.LDAP_SCOPE_BASE;
            if (string.Equals(scope, "Children", StringComparison.OrdinalIgnoreCase))
                return LDAPScope.LDAP_SCOPE_CHILDREN;
            if (string.Equals(scope, "SubTree", StringComparison.OrdinalIgnoreCase))
                return LDAPScope.LDAP_SCOPE_SUBTREE;
            throw new NotImplementedException("scope is: " + scope);
        }

        public override void EstablishConnection()
        {
            connection = new ConnectionHandle(ldap_init(Server, Port), true);
            int version = 3;
            int r = ldap_set_option(connection, 0x11, ref version);
            if (r != 0)
                throw new LDAPException(r);
            var control = new ldapcontrol();
            control.ldctl_oid = Marshal.StringToHGlobalAnsi("1.2.840.113556.1.4.801");
            control.ldctl_iscritical = 1;
            control.ldctl_value = new berval();
            control.ldctl_value.bv_len = 9;
            control.ldctl_value.bv_val = Marshal.AllocHGlobal(control.ldctl_value.bv_len);
            Marshal.Copy(new byte[] { 0x30, 0x84, 0x00, 0x00, 0x00, 0x03, 0x02, 0x01, 0x07 }, 0, control.ldctl_value.bv_val, control.ldctl_value.bv_len);

            var c= Marshal.AllocHGlobal(Marshal.SizeOf(typeof(ldapcontrol)));

            Marshal.StructureToPtr(control, c, true);
            var i = new IntPtr[2] {c, IntPtr.Zero};
            try
            {
                r = ldap_set_option(connection, 0x12, i);
            }
            finally
            {
                if (control.ldctl_oid != IntPtr.Zero)
                    Marshal.FreeHGlobal(control.ldctl_oid);
                if (control.ldctl_value.bv_val != IntPtr.Zero)
                    Marshal.FreeHGlobal(control.ldctl_value.bv_val);
                if (c != IntPtr.Zero)
                    Marshal.FreeHGlobal(c);
            }
            if (r != 0)
                throw new LDAPException(r);
            r = ldap_simple_bind(connection, (string.IsNullOrEmpty(Credential.Domain) ? null : Credential.Domain + "\\") + Credential.UserName, Credential.Password);
            if (r != 0)
                throw new LDAPException(r);
            Trace.WriteLine("Connection OK");

        }

        protected override ADDomainInfo GetDomainInfoInternal()
        {
            IntPtr result;
            var r = ldap_search_s(connection, "", LDAPScope.LDAP_SCOPE_BASE, "(objectclass=*)", null, false, out result);
            if (r != 0)
                throw new LDAPException(r);
            try
            {
                ADDomainInfo info = new ADDomainInfo();
                info.DefaultNamingContext = GetValue(result, "defaultNamingContext");
                info.ConfigurationNamingContext = GetValue(result, "configurationNamingContext");
                info.DnsHostName = GetValue(result, "dnsHostName");
                if (!string.IsNullOrEmpty(GetValue(result, "domainFunctionality")))
                    info.DomainFunctionality = int.Parse(GetValue(result, "domainFunctionality"));
                if (!string.IsNullOrEmpty(GetValue(result, "forestFunctionality")))
                    info.ForestFunctionality = int.Parse(GetValue(result, "forestFunctionality"));
                info.NetBIOSName = GetValue(result, "netBIOSName");
                info.RootDomainNamingContext = GetValue(result, "rootDomainNamingContext");
                info.SchemaNamingContext = GetValue(result, "schemaNamingContext");
                Trace.WriteLine("supportedLDAPVersion: ");
                var supportedLDAPVersion = GetValues(result, "supportedLDAPVersion");
                if (supportedLDAPVersion != null)
                {
                    foreach (string version in supportedLDAPVersion)
                    {
                        Trace.WriteLine(version);
                    }
                }
                Trace.WriteLine("supportedControl: ");
                var supportedControl = GetValues(result, "supportedControl");
                if (supportedControl != null)
                {
                    foreach (string control in supportedControl)
                    {
                        Trace.WriteLine(control);
                    }
                }
                Trace.WriteLine("namingContexts: ");
                info.NamingContexts = new List<string>();
                foreach (var nc in GetValues(result, "namingContexts"))
                {
                    Trace.WriteLine(nc);
                    info.NamingContexts.Add(nc);
                }
                return info;
            }
            finally
            {
                ldap_memfree(result);
            }
        }

        private string GetValue(IntPtr entry, string attr)
        {
            var o = ldap_get_values(connection, entry, attr);
            if (o == IntPtr.Zero)
            {
                // no value for this attribute
                return null;
            }
            var p = Marshal.ReadIntPtr(o);
            if (p == IntPtr.Zero)
                return null;
            var m = Marshal.PtrToStringAnsi(p);
            return m;
        }

        private berval[] GetValueBin(IntPtr entry, string attr)
        {
            var o = ldap_get_values_len(connection, entry, attr);
            if (o == IntPtr.Zero)
            {
                // no value for this attribute
                return null;
            }
            var len = ldap_count_values(o);

            var output = new berval[len];
            for (int i = 0; i < len; i++)
            {
                var p = new IntPtr(o.ToInt64() + i * IntPtr.Size);

                var q = Marshal.ReadIntPtr(p);

                if (q == IntPtr.Zero)
                    return null;

                var r = (berval)Marshal.PtrToStructure(q, typeof(berval));
                output[i] = r;
            }
            return output;
        }

        private List<string> GetValues(IntPtr entry, string attr)
        {
            var o = ldap_get_values(connection, entry, attr);
            if (o == IntPtr.Zero)
            {
                // no value for this attribute
                return null;
            }
            var output = new List<string>();
            for (IntPtr p, o1 = o; (p = Marshal.ReadIntPtr(o1)) != IntPtr.Zero; o1 = new IntPtr(o1.ToInt64() + IntPtr.Size))
            {
                var m = Marshal.PtrToStringAnsi(p);
                output.Add(m);
            }
            return output;
        }

        public LinuxConnection(string Server, int Port, System.Net.NetworkCredential Credential)
        {
            this.Server = Server;
            this.Port = Port;
            this.Credential = Credential;
        }

        LinuxSidResolver sidResolver;
        public override string ConvertSIDToName(string sidstring, out string referencedDomain)
        {
            if (sidResolver == null)
                sidResolver = new LinuxSidResolver(Credential, Server);
            return sidResolver.ConvertSIDToName(sidstring, out referencedDomain);
        }

        public override System.Security.Principal.SecurityIdentifier ConvertNameToSID(string nameToResolve)
        {
            if (sidResolver == null)
                sidResolver = new LinuxSidResolver(Credential, Server);
            return sidResolver.ConvertNameToSid(nameToResolve);
        }

        IFileConnection fileConnection = null;
        public override IFileConnection FileConnection
        {
            get
            {
                if (fileConnection == null)
                    fileConnection = new LinuxFileConnection(this.Credential, domainInfo);
                return fileConnection;
            }
        }

        internal const string LdapLibrary = "libPingCastleldap";

        internal enum LDAPScope : int
        {
            LDAP_SCOPE_BASE = 0,
            LDAP_SCOPE_ONELEVEL = 1,
            LDAP_SCOPE_SUBTREE = 2,
            LDAP_SCOPE_CHILDREN = 3,
        }

        [DllImport(LdapLibrary, EntryPoint = "ldap_initialize", CharSet = CharSet.Ansi, SetLastError = true)]
        internal static extern int ldap_initialize(out IntPtr ld, string hostname);

        [DllImport(LdapLibrary, EntryPoint = "ldap_init", CharSet = CharSet.Ansi, SetLastError = true)]
        internal static extern IntPtr ldap_init(string hostName, int portNumber);

        [DllImport(LdapLibrary, EntryPoint = "ldap_unbind_ext_s", CharSet = CharSet.Ansi)]
        internal static extern int ldap_unbind_ext_s(IntPtr ld, ref IntPtr serverctrls, ref IntPtr clientctrls);

        [DllImport(LdapLibrary, EntryPoint = "ldap_get_dn", CharSet = CharSet.Ansi)]
        internal static extern IntPtr ldap_get_dn([In] ConnectionHandle ldapHandle, [In] IntPtr result);

        [DllImport(LdapLibrary, EntryPoint = "ldap_get_values_len", CharSet = CharSet.Ansi)]
        internal static extern IntPtr ldap_get_values_len([In] ConnectionHandle ldapHandle, [In] IntPtr result, string name);

        [DllImport(LdapLibrary, EntryPoint = "ldap_get_values", CharSet = CharSet.Ansi)]
        internal static extern IntPtr ldap_get_values([In] ConnectionHandle ldapHandle, [In] IntPtr entry, string attr);

        [DllImport(LdapLibrary, EntryPoint = "ldap_search_s", CharSet = CharSet.Ansi)]
        internal static extern int ldap_search_s([In] ConnectionHandle ldapHandle, string dn, LDAPScope scope, string filter, string[] attributes, bool attributeOnly, out IntPtr result);

        [DllImport(LdapLibrary, EntryPoint = "ldap_simple_bind_s", CharSet = CharSet.Ansi, SetLastError = true)]
        internal static extern int ldap_simple_bind([In] ConnectionHandle ld, string who, string passwd);

        [DllImport(LdapLibrary, EntryPoint = "ldap_bind_s", CharSet = CharSet.Ansi, SetLastError = true)]
        internal static extern int ldap_bind_s([In] ConnectionHandle ld, string who, string passwd, int method);

        [DllImport(LdapLibrary, EntryPoint = "ldap_err2string", CharSet = CharSet.Ansi)]
        internal static extern IntPtr ldap_err2string(int err);

        [DllImport(LdapLibrary, EntryPoint = "ldap_count_entries", CharSet = CharSet.Ansi)]
        internal static extern int ldap_count_entries([In] ConnectionHandle ldapHandle, [In] IntPtr entry);

        [DllImport(LdapLibrary, EntryPoint = "ldap_first_attribute", CharSet = CharSet.Ansi)]
        internal static extern IntPtr ldap_first_attribute([In] ConnectionHandle ldapHandle, [In] IntPtr result, ref IntPtr address);

        [DllImport(LdapLibrary, EntryPoint = "ldap_first_entry", CharSet = CharSet.Ansi)]
        internal static extern IntPtr ldap_first_entry([In] ConnectionHandle ldapHandle, [In] IntPtr result);

        [DllImport(LdapLibrary, EntryPoint = "ldap_first_reference", CharSet = CharSet.Ansi)]
        internal static extern IntPtr ldap_first_reference([In] ConnectionHandle ldapHandle, [In] IntPtr result);

        [DllImport(LdapLibrary, EntryPoint = "ldap_value_free", CharSet = CharSet.Ansi)]
        internal static extern int ldap_value_free([In] IntPtr value);

        [DllImport(LdapLibrary, EntryPoint = "ldap_value_free_len", CharSet = CharSet.Ansi)]
        internal static extern IntPtr ldap_value_free_len([In] IntPtr berelement);

        [DllImport(LdapLibrary, EntryPoint = "ldap_memfree", CharSet = CharSet.Ansi)]
        internal static extern void ldap_memfree([In] IntPtr value);

        [DllImport(LdapLibrary, EntryPoint = "ldap_next_entry", CharSet = CharSet.Ansi)]
        internal static extern IntPtr ldap_next_entry([In] ConnectionHandle ldapHandle, [In] IntPtr result);

        [DllImport(LdapLibrary, EntryPoint = "ldap_count_values", CharSet = CharSet.Ansi)]
        internal static extern int ldap_count_values([In] IntPtr values);

        [DllImport(LdapLibrary, EntryPoint = "ldap_set_option", CharSet = CharSet.Ansi)]
        internal static extern int ldap_set_option(ConnectionHandle ldapHandle, int option, ref int invalue);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        internal struct ldapcontrol {
            public IntPtr ldctl_oid;
            public berval ldctl_value;
            public byte ldctl_iscritical;
        } 

        [DllImport(LdapLibrary, EntryPoint = "ldap_set_option", CharSet = CharSet.Ansi)]
        internal static extern int ldap_set_option(ConnectionHandle ldapHandle, int option, IntPtr[] alue);

        internal sealed class ConnectionHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            internal bool _needDispose;

            internal ConnectionHandle()
                : base(true)
            {
                ldap_initialize(out handle, null);
                _needDispose = true;
            }

            internal ConnectionHandle(IntPtr value, bool disposeHandle)
                : base(true)
            {
                _needDispose = disposeHandle;
                if (value == IntPtr.Zero)
                {
                    throw new ApplicationException("Unable to connect");
                }
                else
                {
                    SetHandle(value);
                }
            }

            protected override bool ReleaseHandle()
            {
                if (_needDispose)
                {
                    IntPtr nullPointer = IntPtr.Zero;
                    ldap_unbind_ext_s(handle, ref nullPointer, ref nullPointer);
                }

                handle = IntPtr.Zero;
                return true;
            }
        }

        internal class LDAPException : Exception
        {
            public LDAPException(int code)
                : base("LDAP Error " + code + " (" + Marshal.PtrToStringAnsi(ldap_err2string(code)) + ")")
            {
            }
        }


        public override void ThreadInitialization()
        {
            
        }
    }


}
