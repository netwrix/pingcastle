//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices;
using System.Net;
using System.Security.Permissions;
using System.Text;

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
					entry = new DirectoryEntry(@"LDAP://" + Server + (Port == 0 ? null : ":" + Port) + "/" + distinguishedName, null, null, AuthenticationTypes.ServerBind | AuthenticationTypes.Secure | (Port == 636 ? AuthenticationTypes.SecureSocketsLayer:0));
				}
				else
				{
					entry = new DirectoryEntry(@"LDAP://" + Server + (Port == 0 ? null : ":" + Port) + "/" + distinguishedName, Credential.UserName, Credential.Password, AuthenticationTypes.ServerBind | AuthenticationTypes.Secure | (Port == 636 ? AuthenticationTypes.SecureSocketsLayer : 0));
				}

				DirectorySearcher clsDS = new DirectorySearcher(entry);
				clsDS.SearchRoot = entry;
				clsDS.Filter = filter;
				clsDS.PageSize = 500;
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
				foreach (string property in properties)
				{
					clsDS.PropertiesToLoad.Add(property);
					// prepare the flag for the ntsecuritydescriptor
					if (String.Compare("nTSecurityDescriptor", property, true) == 0)
					{
						nTSecurityDescriptor = true;
					}
				}
				Trace.WriteLine("[" + DateTime.Now.ToLongTimeString() + "]Calling FindAll");
				foreach (SearchResult sr in clsDS.FindAll())
				{
					ADItem aditem = null;
					try
					{
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
			DirectoryEntry rootDse = new DirectoryEntry("LDAP://" + Server + "/RootDSE");
			if (Credential == null)
			{
				rootDse = new DirectoryEntry(@"LDAP://" + Server + (Port == 0 ? null : ":" + Port) + "/RootDSE", null, null, AuthenticationTypes.ServerBind | AuthenticationTypes.Secure | (Port == 636 ? AuthenticationTypes.SecureSocketsLayer : 0));
			}
			else
			{
				rootDse = new DirectoryEntry(@"LDAP://" + Server + (Port == 0 ? null : ":" + Port) + "/RootDSE", Credential.UserName, Credential.Password, AuthenticationTypes.ServerBind | AuthenticationTypes.Secure | (Port == 636 ? AuthenticationTypes.SecureSocketsLayer : 0));
			}
			return ADDomainInfo.Create(rootDse);
		}

		// connecting using LDAP
		public override void EstablishConnection()
		{
			GetDomainInfo();
			// in case the domain has been set (instead of the FQDN of the DC), set it to the DC for optimization purpose
			if (Uri.CheckHostName(Server) == UriHostNameType.Dns)
			{
				Server = domainInfo.DnsHostName;
			}
		}
	}
}
