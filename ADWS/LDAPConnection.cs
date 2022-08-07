//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Diagnostics;
using System.DirectoryServices;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Permissions;

namespace PingCastle.ADWS
{
    public class LDAPConnection : ADConnection
    {
        public LDAPConnection(string server, int port, NetworkCredential credential)
        {
            Server = server;
            Port = port;
            Credential = credential;
        }
        public static int PageSize = 500;

        public override void Enumerate(string distinguishedName, string filter, string[] properties, WorkOnReturnedObjectByADWS callback, string scope)
        {
            EnumerateInternalWithLDAP(distinguishedName, filter, properties, scope, callback);
        }

        [SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        private void EnumerateInternalWithLDAP(string distinguishedName, string filter, string[] properties, string scope, WorkOnReturnedObjectByADWS callback)
        {
            Trace.WriteLine("[" + DateTime.Now.ToLongTimeString() + "] Running ldap enumeration");
            Trace.WriteLine("BaseObject=" + scope);
            Trace.WriteLine("Filter=" + filter);
            DirectoryEntry entry;
            int numberOfObjectAlreadyExtracted = 0;
            try
            {
                if (Credential == null)
                {
                    entry = new DirectoryEntry(@"LDAP://" + Server + (Port == 0 ? null : ":" + Port) + "/" + distinguishedName, null, null, AuthenticationTypes.ServerBind | AuthenticationTypes.Secure | (Port == 636 ? AuthenticationTypes.SecureSocketsLayer : 0));
                }
                else
                {
                    entry = new DirectoryEntry(@"LDAP://" + Server + (Port == 0 ? null : ":" + Port) + "/" + distinguishedName, Credential.UserName, Credential.Password, AuthenticationTypes.ServerBind | AuthenticationTypes.Secure | (Port == 636 ? AuthenticationTypes.SecureSocketsLayer : 0));
                }

                DirectorySearcher clsDS = new DirectorySearcher(entry);
                clsDS.SearchRoot = entry;
                clsDS.Filter = filter;
                clsDS.PageSize = PageSize;
                switch (scope)
                {
                    case "OneLevel":
                        clsDS.SearchScope = SearchScope.OneLevel;
                        break;
                    case "SubTree":
                        clsDS.SearchScope = SearchScope.Subtree;
                        break;
                    case "Base":
                        clsDS.SearchScope = SearchScope.Base;
                        break;
                }

                bool nTSecurityDescriptor = false;
                if (properties != null)
                {
                    foreach (string property in properties)
                    {
                        clsDS.PropertiesToLoad.Add(property);
                        // prepare the flag for the ntsecuritydescriptor
                        if (String.Compare("nTSecurityDescriptor", property, true) == 0)
                        {
                            nTSecurityDescriptor = true;
                        }
                    }
                }
                Trace.WriteLine("[" + DateTime.Now.ToLongTimeString() + "]Calling FindAll");
                var iterator = clsDS.FindAll().GetEnumerator();
                while(true)
                {
                    try
                    {
                        if (!iterator.MoveNext())
                            break;
                    }
                    catch (DirectoryServicesCOMException ex)
                    {
                        if (ex.ErrorCode == -2147024662 && ex.ExtendedError == 234)
                        {
                            Console.ForegroundColor = ConsoleColor.Yellow;
                            Console.WriteLine("[" + DateTime.Now.ToLongTimeString() + "] Warning: received \"Calling GetNextRow can potentially return more results\"");
                            Trace.WriteLine("[" + DateTime.Now.ToLongTimeString() + "] Warning: received \"Calling GetNextRow can potentially return more results\"");
                            Console.ResetColor();
                            if (!iterator.MoveNext())
                            {
                                Console.WriteLine("[" + DateTime.Now.ToLongTimeString() + "] No more results");
                                Trace.WriteLine("[" + DateTime.Now.ToLongTimeString() + "] No more results");
                                break;
                            }
                            Console.WriteLine("[" + DateTime.Now.ToLongTimeString() + "] More results found");
                            Trace.WriteLine("[" + DateTime.Now.ToLongTimeString() + "] More results found");
                        }
                        else
                        {
                            throw;
                        }
                    }
                    var sr = (SearchResult) iterator.Current;
                    ADItem aditem = null;
                    try
                    {
                        OneRecord();
                        aditem = ADItem.Create(sr, nTSecurityDescriptor);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("Warning: unable to process element (" + ex.Message + ")\r\n" + sr.Path);
                        Trace.WriteLine("Warning: unable to process element\r\n" + sr.Path);
                        Trace.WriteLine("Exception: " + ex.Message);
                        Trace.WriteLine(ex.StackTrace);
                    }
                    if (aditem != null)
                        callback(aditem);
                    numberOfObjectAlreadyExtracted++;
                }
                Trace.WriteLine("[" + DateTime.Now.ToLongTimeString() + "]Enumeration successful");
            }
            catch (DirectoryServicesCOMException ex)
            {
                Trace.WriteLine("[" + DateTime.Now.ToLongTimeString() + "]An exception occured");
                Trace.WriteLine("ErrorCode: " + ex.ErrorCode);
                Trace.WriteLine("ExtendedError: " + ex.ExtendedError);
                Trace.WriteLine("ExtendedErrorMessage: " + ex.ExtendedErrorMessage);
                Trace.WriteLine("numberOfObjectAlreadyExtracted=" + numberOfObjectAlreadyExtracted);
                if (ex.ErrorCode == -2147023570)
                {
                    Trace.WriteLine("Translating DirectoryServicesCOMException to UnauthorizedAccessException");
                    throw new UnauthorizedAccessException(ex.Message);
                }
                if (ex.ErrorCode == -2147016656)
                {
                    // no such object
                    Trace.WriteLine(ex.Message);
                    return;
                }
                throw;
            }
        }

        protected override ADDomainInfo GetDomainInfoInternal()
        {
            return GetLDAPDomainInfo();
        }

        [SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        private ADDomainInfo GetLDAPDomainInfo()
        {
            DirectoryEntry rootDse;
            try
            {
                if (Credential == null)
                {
                    rootDse = new DirectoryEntry(@"LDAP://" + Server + (Port == 0 ? null : ":" + Port) + "/RootDSE", null, null, AuthenticationTypes.ServerBind | AuthenticationTypes.Secure | (Port == 636 ? AuthenticationTypes.SecureSocketsLayer : 0));
                }
                else
                {
                    rootDse = new DirectoryEntry(@"LDAP://" + Server + (Port == 0 ? null : ":" + Port) + "/RootDSE", Credential.UserName, Credential.Password, AuthenticationTypes.ServerBind | AuthenticationTypes.Secure | (Port == 636 ? AuthenticationTypes.SecureSocketsLayer : 0));
                }
                // force the connection to the LDAP server via an access to the "properties" property
                Trace.WriteLine("rootDse property count: " + rootDse.Properties.Count);
            }
            catch (COMException ex)
            {
                // Windows 2000 does not support a bind to the rootDse and returns "The server is not operational" (0x8007203A)
                if (ex.ErrorCode == -2147016646)
                {
                    if (Credential == null)
                    {
                        rootDse = new DirectoryEntry(@"LDAP://" + Server + (Port == 0 ? null : ":" + Port) + "/RootDSE", null, null, AuthenticationTypes.Secure | (Port == 636 ? AuthenticationTypes.SecureSocketsLayer : 0));
                    }
                    else
                    {
                        rootDse = new DirectoryEntry(@"LDAP://" + Server + (Port == 0 ? null : ":" + Port) + "/RootDSE", Credential.UserName, Credential.Password, AuthenticationTypes.Secure | (Port == 636 ? AuthenticationTypes.SecureSocketsLayer : 0));
                    }
                }
                else
                {
                    throw;
                }
            }
            return ADDomainInfo.Create(rootDse);
        }

        // connecting using LDAP
        [SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        public override void EstablishConnection()
        {
            var serverType = Uri.CheckHostName(Server);
            if (serverType != UriHostNameType.Dns)
            {
                Trace.WriteLine("Server is not DNS - direct connection");
                GetDomainInfo();
                return;
            }
            Trace.WriteLine("Locating a DC");
            try
            {
                Server = DomainLocator.GetDC(Server, false, false);
            }
            catch (Exception)
            {
                Trace.WriteLine("The domain location didn't worked - trying it directly");
                GetDomainInfo();
                return;
            }
            for (int i = 0; i < 2; i++)
            {
                try
                {
                    Trace.WriteLine("Trying " + Server);
                    GetDomainInfo();
                    Trace.WriteLine("The connection worked");
                    return;
                }
                catch (COMException ex)
                {
                    // server not available - force rediscovery of DC
                    if ((uint)ex.ErrorCode == 0x8007203a)
                    {
                        if (i == 0)
                        {
                            // if we coulnd't connect to the select DC, even after a refresh, go to exception
                            Trace.WriteLine("Unable to connect - force rediscovery of DC");
                        }
                        else
                        {
                            throw;
                        }
                    }
                    else
                    {
                        throw;
                    }
                }
                if (i > 0)
                    Server = DomainLocator.GetDC(Server, false, true);
            }
        }

        public override string ConvertSIDToName(string sidstring, out string referencedDomain)
        {
            return NativeMethods.ConvertSIDToNameWithWindowsAPI(sidstring, Server, out referencedDomain);
        }

        public override System.Security.Principal.SecurityIdentifier ConvertNameToSID(string nameToResolve)
        {
            return NativeMethods.GetSidFromDomainNameWithWindowsAPI(Server, nameToResolve);
        }

        IFileConnection fileConnection = null;
        public override IFileConnection FileConnection
        {
            get
            {
                if (fileConnection == null)
                    fileConnection = new WindowsFileConnection(this.Credential, Server);
                return fileConnection;
            }
        }

        public override void ThreadInitialization()
        {
            FileConnection.ThreadInitialization();
        }
    }
}
