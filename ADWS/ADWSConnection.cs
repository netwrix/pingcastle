//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Reflection;
using System.Security.Permissions;
using System.Security.Principal;
using System.ServiceModel;
using System.Xml;
using PingCastle.UserInterface;

namespace PingCastle.ADWS
{
    public class ADWSConnection : ADConnection
	{
		
		public ADWSConnection(string server, int port, NetworkCredential credential)
		{
			Server = server;
			Port = port;
			Credential = credential;
		}

		public bool DomainScope { get; set; }

		private delegate void ReceiveItems(ItemListType items);

        private readonly IUserInterface _ui = UserInterfaceFactory.GetUserInterface();

        // when doing a simple enumeration, ws-transfert (for root dse) and ws-enumeration needs to be called.
        // share the connection between the 2 webservices to save time
        private NetTcpBinding _binding = null;
		private NetTcpBinding Binding
		{
			get
			{
				if (_binding == null)
				{
					// initialize the "socket"
					_binding = new NetTcpBinding();
					// ADWS max sent message size (from our side = receive) : 32MB
					// max received (from our side sent): 1048576 bytes
					// max interval between 2 pull request: 2 minutes
					// interval without activity : 10 minutes
					// max time for enumeration without renew : 30 minutes
					_binding.MaxReceivedMessageSize = 32000000;
					//tcpBind.Security.Mode = SecurityMode.Message;
					_binding.Security.Message.ClientCredentialType = MessageCredentialType.Windows;
				}
				return _binding;
			}
		}

		// connection to the ws-enumeration service
		// connection automatically opened
		private SearchClient _search = null;
		private SearchClient Search
		{
			get
			{
				if (_search == null)
				{
					UriBuilder uriBuilder = new UriBuilder();
					uriBuilder.Scheme = "net.tcp";
					uriBuilder.Host = Server;
					uriBuilder.Port = (Port > 0 ? Port : 9389);

					// setting up the ws-enumeration service (enumerate objects)
					uriBuilder.Path = "ActiveDirectoryWebServices/Windows/Enumeration";
					Trace.WriteLine("Connecting to " + uriBuilder.Uri);

					_search = new SearchClient(Binding, new EndpointAddress(uriBuilder.Uri));
					if (Credential != null)
					{
						_search.ClientCredentials.Windows.ClientCredential.UserName = Credential.UserName;
						_search.ClientCredentials.Windows.ClientCredential.Password = Credential.Password;
						_search.ClientCredentials.Windows.ClientCredential.Domain = Credential.Domain;
					}
					_search.ClientCredentials.Windows.AllowedImpersonationLevel = System.Security.Principal.TokenImpersonationLevel.Impersonation;

					// add the ad:instance soap header
					SoapHeader[] soapHeaders = new SoapHeader[] {
                           new SoapHeader("instance", "http://schemas.microsoft.com/2008/1/ActiveDirectory", "ldap:389"),
                    };
					_search.ChannelFactory.Endpoint.Behaviors.Add(new SoapHeaderBehavior(soapHeaders));
				}
				return _search;
			}
		}

		// connection to the ws-transfert service
		// connection automatically opened
		private ResourceClient _resource = null;
		private ResourceClient Resource
		{
			get
			{
				if (_resource == null)
				{
					UriBuilder uriBuilder = new UriBuilder();
					uriBuilder.Scheme = "net.tcp";
					uriBuilder.Host = Server;
					uriBuilder.Port = (Port > 0 ? Port : 9389);

					// setting up the ws-enumeration service (enumerate objects)
					uriBuilder.Path = "/ActiveDirectoryWebServices/Windows/Resource";
					Trace.WriteLine("Connecting to " + uriBuilder.Uri);

					_resource = new ResourceClient(Binding, new EndpointAddress(uriBuilder.Uri));
					if (Credential != null)
					{
						_resource.ClientCredentials.Windows.ClientCredential.UserName = Credential.UserName;
						_resource.ClientCredentials.Windows.ClientCredential.Password = Credential.Password;
						_resource.ClientCredentials.Windows.ClientCredential.Domain = Credential.Domain;
					}
					_resource.ClientCredentials.Windows.AllowedImpersonationLevel = System.Security.Principal.TokenImpersonationLevel.Impersonation;

					// add the ad:instance & ad:objectReference soap header
					SoapHeader[] soapHeaders = new SoapHeader[] {
                           new SoapHeader("instance", "http://schemas.microsoft.com/2008/1/ActiveDirectory", "ldap:389"),
                           new SoapHeader("objectReferenceProperty", "http://schemas.microsoft.com/2008/1/ActiveDirectory", "11111111-1111-1111-1111-111111111111"),
                    };
					_resource.ChannelFactory.Endpoint.Behaviors.Add(new SoapHeaderBehavior(soapHeaders));
				}
				return _resource;
			}
		}

		// connection to the topology service
		// connection automatically opened
		private TopologyManagementClient _topology = null;
		private TopologyManagementClient Topology
		{
			get
			{
				if (_topology == null)
				{
					UriBuilder uriBuilder = new UriBuilder();
					uriBuilder.Scheme = "net.tcp";
					uriBuilder.Host = Server;
					uriBuilder.Port = (Port > 0 ? Port : 9389);

					// setting up the ws-enumeration service (enumerate objects)
					uriBuilder.Path = "ActiveDirectoryWebServices/Windows/TopologyManagement";
					Trace.WriteLine("Connecting to " + uriBuilder.Uri);

					_topology = new TopologyManagementClient(Binding, new EndpointAddress(uriBuilder.Uri));
					if (Credential != null)
					{
						_topology.ClientCredentials.Windows.ClientCredential.UserName = Credential.UserName;
						_topology.ClientCredentials.Windows.ClientCredential.Password = Credential.Password;
						_topology.ClientCredentials.Windows.ClientCredential.Domain = Credential.Domain;
					}
					_topology.ClientCredentials.Windows.AllowedImpersonationLevel = System.Security.Principal.TokenImpersonationLevel.Impersonation;
				}
				return _topology;
			}
		}

		// connecting using ADWS
		// this function is here to optimize the connection
		// in a domain with W2003, ... not every server has ADWS installed
		// each binding try to resolve the dns entry which is taking some time ..
		// the trick is to test each ip and to assign a working one as the server
		[SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.UnmanagedCode)]
		public override void EstablishConnection()
		{
			if (Uri.CheckHostName(Server) != UriHostNameType.Dns)
			{
				Trace.WriteLine("Server is not a DNS entry - checking it directly");
				GetDomainInfo();
				return;
			}
			Trace.WriteLine("Trying to locate the domain");
            Trace.WriteLine("Locating a DC");
			try
			{
				Server = DomainLocator.GetDC(Server, true, false);
			}
			catch(Exception)
			{
				Trace.WriteLine("The domain location didn't work - trying it directly");
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
				catch (EndpointNotFoundException)
				{
					Trace.WriteLine("The connection didn't work");
					CleanConnection<Resource>(_resource);
					_resource = null;
				}
				catch (Exception ex)
				{
					Trace.WriteLine("Exception: " + ex.Message);
					Trace.WriteLine("Type: " + ex.GetType().ToString());
					Trace.WriteLine("The connection didn't work");
					CleanConnection<Resource>(_resource);
					_resource = null;
				}
				if (i > 0)
                    Server = DomainLocator.GetDC(Server, true, true);
			}
            // if we coulnd't connect to the select DC, even after a refresh, go to exception
            throw new EndpointNotFoundException();
		}

		public override void Enumerate(string distinguishedName, string filter, string[] properties, WorkOnReturnedObjectByADWS callback, string scope)
		{
			EnumerateInternalWithADWS(distinguishedName, filter, properties, scope,
				(ItemListType items) =>
				{
					if (items != null)
					{
						foreach (XmlElement item in items.Any)
						{
							ADItem aditem = null;
							try
							{
                                OneRecord();
								aditem = ADItem.Create(item);
							}
							catch (Exception ex)
							{
                                _ui.DisplayWarning("Warning: unable to process element (" + ex.Message + ")\r\n" + item.OuterXml);
								Trace.WriteLine("Warning: unable to process element\r\n" + item.OuterXml);
								Trace.WriteLine("Exception: " + ex.ToString());
							}
                            if (aditem != null)
                            {
                                try
                                {
                                    callback(aditem);
                                }
                                catch
                                {
                                    Trace.WriteLine("Exception while working on " + aditem.DistinguishedName);
                                    throw;
                                }
                            }
						}
					}
				}
			);
		}

		XmlQualifiedName[] BuildProperties(List<string> properties)
		{
			var output = new XmlQualifiedName[properties.Count];
			for (int i = 0; i < properties.Count; i++)
			{
				if (properties[i] == "distinguishedName")
					output[i] = new XmlQualifiedName("distinguishedName", "http://schemas.microsoft.com/2008/1/ActiveDirectory");
				else
					output[i] = new XmlQualifiedName(properties[i], "http://schemas.microsoft.com/2008/1/ActiveDirectory/Data");
			}
			return output;
		}

		private void EnumerateInternalWithADWS(string distinguishedName, string filter, string[] properties, string scope, ReceiveItems callback)
		{
			bool nTSecurityDescriptor = false;
			List<string> listproperties = new List<string>();

			Enumerate enumerate = new Enumerate();
			enumerate.Filter = new FilterType();
			enumerate.Filter.LdapQuery = new LdapQuery();
			enumerate.Filter.LdapQuery.BaseObject = distinguishedName;
			Trace.WriteLine("LdapQuery.BaseObject=" + enumerate.Filter.LdapQuery.BaseObject);

			enumerate.Filter.LdapQuery.Scope = scope;
			enumerate.Filter.LdapQuery.Filter = filter;
			Trace.WriteLine("LdapQuery.Filter=" + enumerate.Filter.LdapQuery.Filter);

			if (properties != null)
			{
				listproperties.AddRange(properties);
				enumerate.Selection = new Selection();

				enumerate.Selection.SelectionProperty = BuildProperties(listproperties);
			}
			EnumerateResponse enumerateResponse = null;

			Trace.WriteLine("[" + DateTime.Now.ToLongTimeString() + "] Running enumeration");
			bool hasNewProperties = true;
			while (hasNewProperties)
			{
				try
				{
					enumerateResponse = Search.Enumerate(enumerate);
					hasNewProperties = false;
				}
				catch (FaultException<schemas.microsoft.com._2008._1.ActiveDirectory.EnumerateFault> ex)
				{
					// handle the case where the property is not available in the schema.
					// an exception is thrown
					// remove the litigious property and resume the query
					Trace.WriteLine("The server doesn't support the property: " + ex.Detail.InvalidProperty);
					int postns = ex.Detail.InvalidProperty.IndexOf(':');
					string property = ex.Detail.InvalidProperty;
					if (postns > 0)
						property = ex.Detail.InvalidProperty.Substring(postns + 1);
					if (!listproperties.Remove(property))
						throw;
					if (listproperties.Count == 0)
						return;
					enumerate.Selection.SelectionProperty = BuildProperties(listproperties);
				}
			}
			Trace.WriteLine("[" + DateTime.Now.ToLongTimeString() + "]Enumeration successful");
			Trace.WriteLine("Enumeration expires at " + enumerateResponse.Expires);
			Trace.WriteLine("Enumeration context is " + String.Join(",", enumerateResponse.EnumerationContext.Text));

			// prepare the flag for the ntsecuritydescriptor
			foreach (string property in listproperties)
			{
				if (String.Compare("nTSecurityDescriptor", property, true) == 0)
				{
					nTSecurityDescriptor = true;
				}
			}

			// do not fail if the expiration cannot be parsed
			DateTime expiration = DateTime.Now.AddMinutes(30);
			DateTime.TryParse(enumerateResponse.Expires, out expiration);

			bool bcontinue = true;
			int pagenum = 0;
			while (bcontinue)
			{
				if (expiration.AddMinutes(-5) < DateTime.Now)
				{
					Trace.WriteLine("[" + DateTime.Now.ToLongTimeString() + "]Renewing the enumeration (expiration)");
					Renew renew = new Renew();
					renew.EnumerationContext = enumerateResponse.EnumerationContext;
					renew.Expires = DateTime.Now.AddMinutes(20).ToString("O");
					RenewResponse renewresponse = Search.Renew(renew);
					Trace.WriteLine("New expiration at " + renewresponse.Expires);
					DateTime.TryParse(renewresponse.Expires, out expiration);
					Trace.WriteLine("New enumeration context " + String.Join(",", renewresponse.EnumerationContext.Text));
					enumerateResponse.EnumerationContext = renewresponse.EnumerationContext;

				}
				Trace.WriteLine("[" + DateTime.Now.ToLongTimeString() + "]Getting Enumerate page " + pagenum);
				Pull pull = new Pull();
				pull.EnumerationContext = enumerateResponse.EnumerationContext;
                pull.MaxElements = LDAPConnection.PageSize.ToString();
				if (nTSecurityDescriptor || DomainScope)
				{

					List<controlsControl> controls = new List<controlsControl>();
					if (nTSecurityDescriptor)
					{
						// this is the flag https://msdn.microsoft.com/en-us/library/cc223323.aspx
						// the last byte, 0x07, is OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
						controlsControl control = new controlsControl();
						controls.Add(control);
						control.controlValue = Convert.ToBase64String(new byte[] { 0x30, 0x84, 0x00, 0x00, 0x00, 0x03, 0x02, 0x01, 0x07 });
						control.criticality = true;
						control.type = "1.2.840.113556.1.4.801";
					}
					if (DomainScope)
					{
						// this is the flag https://msdn.microsoft.com/en-us/library/cc223323.aspx
						// the last byte, 0x07, is OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
						controlsControl control = new controlsControl();
						controls.Add(control);
						control.criticality = true;
						control.type = "1.2.840.113556.1.4.1339";
					}
					pull.controls = controls.ToArray();
				}

				PullResponse pullResponse = null;
				try
				{
					pullResponse = Search.Pull(pull);
				}
				catch (FaultException ex)
				{
					Trace.WriteLine("[" + DateTime.Now.ToLongTimeString() + "]Pull unsuccessful");
					Trace.WriteLine("Fault Exception: " + ex.Message);
					Trace.WriteLine("Reason: " + ex.Reason);
					var stringWriter = new StringWriter();
					var xmlTextWriter = new XmlTextWriter(stringWriter);
					var messageFault = ex.CreateMessageFault();
					messageFault.WriteTo(xmlTextWriter, EnvelopeVersion.Soap12);
					var stringValue = Convert.ToString(stringWriter);
					Trace.WriteLine("Detail:");
					Trace.WriteLine(stringValue);
                    var detail = messageFault.GetDetail<schemas.microsoft.com._2008._1.ActiveDirectory.FaultDetail>();
                    // non existing object - do not throw an exception if the object does not exist
                    if (detail != null && detail.DirectoryError != null)
                    {
                        var de = detail.DirectoryError;
                        foreach (var node in detail.DirectoryError.Nodes)
                        {
                            if (node.Name == "Win32ErrorCode")
                            {
                                string error = node.InnerText;
                                if (error == "8240")
                                {
                                    return;
                                }
                                break;
                            }
                        }
                    }
					throw new PingCastleException("An ADWS exception occured (fault:" + ex.Message + ";reason:" + ex.Reason + ").\r\nADWS is a faster protocol than LDAP but bound to a default 30 minutes limitation. If this error persists, we recommend to force the LDAP protocol. Run PingCastle with the following switches: --protocol LDAPOnly --interactive");
				}
				Trace.WriteLine("[" + DateTime.Now.ToLongTimeString() + "]Pull successful");
				if (pullResponse.EndOfSequence != null)
				{
					bcontinue = false;
				}
				callback(pullResponse.Items);
				pagenum++;

			}
			Trace.WriteLine("[" + DateTime.Now.ToLongTimeString() + "]Releasing the enumeration context");
			Release relase = new Release();
			relase.EnumerationContext = enumerateResponse.EnumerationContext;
			Search.Release(relase);
		}

		protected override ADDomainInfo GetDomainInfoInternal()
		{
			try
			{
				var data = Resource.Get();
				return ADDomainInfo.Create(data);
			}
			catch (FaultException ex)
			{
				Trace.WriteLine("Fault Exception: " + ex.Message);
				Trace.WriteLine("Reason: " + ex.Reason);
				var stringWriter = new StringWriter();
				var xmlTextWriter = new XmlTextWriter(stringWriter);
				var messageFault = ex.CreateMessageFault();
				messageFault.WriteTo(xmlTextWriter, EnvelopeVersion.Soap12);
				var stringValue = Convert.ToString(stringWriter);
				Trace.WriteLine("Exception:");
				Trace.WriteLine(stringValue);
				Trace.WriteLine("The connection didn't work");
				throw;
			}
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

        void CleanConnection<TChannel>(ClientBase<TChannel> c) where TChannel : class
        {
            if (c != null)
            {
                try
                {
                    if (c.State != CommunicationState.Faulted) c.Close();
                }
                catch
                {
                    c.Abort();
                }
            }
        }
    }
}
