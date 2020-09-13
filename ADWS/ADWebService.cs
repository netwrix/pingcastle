//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.misc;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Security;
using System.Text;
using System.Threading;
using System.Xml;
using System.Xml.Serialization;

namespace PingCastle.ADWS
{
    public delegate void WorkOnReturnedObjectByADWS(ADItem Object);

    public enum ADConnectionType
    {
        ADWSThenLDAP = 0, 
        ADWSOnly = 1,
        LDAPOnly = 2,
        LDAPThenADWS = 3
    }

	public class ADWebService : IDisposable, IADConnection
    {

        public ADWebService(string server, int port, NetworkCredential credential)
        {
            Server = server;
            Port = port;
            Credential = credential;
			Trace.WriteLine("Before establishing connection");
            EstablishConnection();
        }

        public static ADConnectionType ConnectionType { get; set; }

        public string Server { get; set; }

        public int Port { get; set; }

        public NetworkCredential Credential { get; set; }

		private IADConnection connection { get; set; }
		private IADConnection fallBackConnection { get; set; }

        #region connection establishment
        private void EstablishConnection()
        {
			ADWSConnection adwsConnection = null;
			LDAPConnection ldapConnection = new LDAPConnection(Server, Port, Credential);
			try
			{
				adwsConnection = new ADWSConnection(Server, Port, Credential);
			}
			catch (Exception ex)
			{
				Trace.WriteLine("Unable to load ADWS - .Net 2 only ? (" + ex.Message + ")"); 
			}
            switch (ConnectionType)
            {
                case ADConnectionType.ADWSOnly:
                    Trace.WriteLine("Trying ADWS connection");
					adwsConnection.EstablishConnection();
                    Trace.WriteLine("ADWS connection successful");
					connection = adwsConnection;
                    break;
                case ADConnectionType.LDAPOnly:
                    Trace.WriteLine("Trying LDAP connection");
                    ldapConnection.EstablishConnection();
                    Trace.WriteLine("LDAP connection successful");
					connection = ldapConnection;
                    break;
                case ADConnectionType.ADWSThenLDAP:
                    try
                    {
                        Trace.WriteLine("Trying ADWS connection");
						adwsConnection.EstablishConnection();
                        Trace.WriteLine("ADWS connection successful");
						connection = adwsConnection;
						fallBackConnection = new LDAPConnection(adwsConnection.Server, adwsConnection.Port, Credential);
                    }
                    catch (Exception ex)
                    {
                        Trace.WriteLine("Unable to connect to ADWS - trying LDAP");
                        try
                        {
							ldapConnection.EstablishConnection();
                            Trace.WriteLine("Connected with LDAP");
							connection = ldapConnection;
                        }
                        catch(Exception ex2)
                        {
                            Trace.WriteLine("LDAP exception: " + ex2.Message + "(" + ex2.GetType() + ")");
							if (ex2 as COMException != null)
							{
								COMException ex3 = (COMException)ex2;
								Trace.WriteLine("COMException: " + ex3.ErrorCode);
							}
                            Trace.WriteLine(ex2.StackTrace);
                            Trace.WriteLine("Throwing ADWS Exception again");
							throw new ActiveDirectoryServerDownException(ex.Message);
                        }
                    }
                    break;
                case ADConnectionType.LDAPThenADWS:
                    try
                    {
                        Trace.WriteLine("Trying LDAP connection");
						ldapConnection.EstablishConnection();
                        Trace.WriteLine("LDAP connection successful");
						connection = ldapConnection;
						fallBackConnection = new ADWSConnection(adwsConnection.Server, adwsConnection.Port, Credential);
                    }
                    catch (Exception ex)
                    {
                        Trace.WriteLine("Unable to connect to LDAP - trying ADWS");
                        try
                        {
							adwsConnection.EstablishConnection();
                            Trace.WriteLine("Connected with ADWS");
							connection = adwsConnection;
                        }
                        catch (Exception ex2)
                        {
							Trace.WriteLine("ADWS exception: " + ex2.Message + "(" + ex2.GetType() + ")");
                            Trace.WriteLine(ex2.StackTrace);
                            Trace.WriteLine("Throwing LDAP Exception again");
							throw new ActiveDirectoryServerDownException(ex.Message);
                        }
                    }
                    break;
            }
        }

		public bool useLdap 
		{ 
			get 
			{ 
				return connection != null && connection is LDAPConnection;
			}
		}

        #endregion connection establishment

        // this function is used to test the connection
        // cache the result to avoid 2 calls
        public ADDomainInfo DomainInfo
		{
			get
			{
				if (connection != null)
					return connection.GetDomainInfo();
				return null;
			}
		}

		public ADDomainInfo GetDomainInfo()
		{
			return DomainInfo;
		}

        public class OUExploration: IComparable<OUExploration>
        {
            public string OU { get; set; }
            public string Scope { get; set; }
            public int Level { get; set; }
            public OUExploration(string ou, string scope, int level)
            {
                OU = ou;
                Scope = scope;
                Level = level;
            }
            // revert an OU string order to get a string orderable
            // ex: OU=myOU,DC=DC   => DC=DC,OU=myOU
            private string GetSortKey(string ou)
            {
                string[] apart = ou.Split(',');
                string[] apart1 = new string[apart.Length];
                for (int i = 0; i < apart.Length; i++)
                {
                    apart1[i] = apart[apart.Length - 1 - i];
                }
                return String.Join(",", apart1);
            }
            public int CompareTo(OUExploration other)
            {
                return String.Compare(GetSortKey(OU), GetSortKey(other.OU));
            }
        }

        public List<OUExploration> BuildOUExplorationList(string OU, int NumberOfDepthForSplit)
        {
            List<OUExploration> output = new List<OUExploration>();
            if (NumberOfDepthForSplit == 0)
            {
                output.Add(new OUExploration(OU, "SubTree", 1));
                return output;
            }
            List<string> OUToExplore = new List<string>();
            OUToExplore.Add(OU);
            string[] properties = new string[] {
                        "distinguishedName"
            };
            List<string> futureOuToExplore = null;
            for (int i = 0; i < NumberOfDepthForSplit; i++)
            {
                futureOuToExplore = new List<string>();
                foreach (string ou in OUToExplore)
                {
                    output.Add(new OUExploration(ou, "OneLevel", i));
                    Enumerate(ou, "(|(objectCategory=organizationalUnit)(objectCategory=container)(objectCategory=buitinDomain))", properties,
                        (ADItem x)
                        =>
                        {
                            futureOuToExplore.Add(x.DistinguishedName);
                        }
                        , "OneLevel"
                        );

                }
                OUToExplore = futureOuToExplore;
            }
            foreach (string ou in futureOuToExplore)
            {
                output.Add(new OUExploration(ou, "SubTree", NumberOfDepthForSplit));
            }
            output.Sort();
            return output;
        }

        public void Enumerate(string distinguishedName, string filter, string[] properties, WorkOnReturnedObjectByADWS callback)
        {
            Enumerate(null, distinguishedName, filter, properties, callback, "Subtree");
        }

		public void Enumerate(string distinguishedName, string filter, string[] properties, WorkOnReturnedObjectByADWS callback, string scope)
		{
			Enumerate(null, distinguishedName, filter, properties, callback, scope);
		}

		public delegate void Action();

		public void Enumerate(Action preambleWithReentry, string distinguishedName, string filter, string[] properties, WorkOnReturnedObjectByADWS callback, string scope)
		{
			if (preambleWithReentry != null)
				preambleWithReentry();
			try
			{
				connection.Enumerate(distinguishedName, filter, properties, callback, scope);
			}
			catch (Exception ex)
			{
				Trace.WriteLine("Exception: " + ex.Message);
				Trace.WriteLine("StackTrace: " + ex.StackTrace);
				if (fallBackConnection == null)
					throw;
				Console.ForegroundColor = ConsoleColor.Yellow;
				Console.WriteLine("The AD query failed. Using the alternative protocol (" + fallBackConnection.GetType().Name + ")");
				Console.ResetColor();
				if (preambleWithReentry != null)
					preambleWithReentry();
				fallBackConnection.Enumerate(distinguishedName, filter, properties, callback, scope);
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


		~ADWebService()
        {
            // The object went out of scope and finalized is called
            // Lets call dispose in to release unmanaged resources 
            // the managed resources will anyways be released when GC 
            // runs the next time.
            Dispose(false);
        }
        #endregion IDispose
    }
}
