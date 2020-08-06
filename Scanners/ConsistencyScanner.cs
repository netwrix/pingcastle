/*
 * //
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.ADWS;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices;
using System.IO;
using System.Net;
using System.Text;

namespace PingCastle.Scanners
{
	public class ConsistencyScanner : IScanner
	{
		public string Name { get { return "corruptADDatabase"; } }
		public string Description { get { return "Try to detect corrupted AD database. To run only when requested by PingCastle support."; } }

		public string Server { get; private set; }
		public int Port { get; private set; }
		public NetworkCredential Credential { get; private set; }

		public void Initialize(string server, int port, NetworkCredential credential)
		{
			Server = server;
			Port = port;
			Credential = credential;
		}

		public bool QueryForAdditionalParameterInInteractiveMode()
		{
			return true;
		}

		public void Export(string filename)
		{

			ADDomainInfo domainInfo = null;
			DisplayAdvancement("Starting");
			ADWebService.ConnectionType = ADConnectionType.LDAPOnly;

			using (ADWebService adws = new ADWebService(Server, Port, Credential))
			{
				DisplayAdvancement("Connected");
				domainInfo = adws.DomainInfo;
				DisplayAdvancement("Building a list of all OU");
				var exploration = adws.BuildOUExplorationList(domainInfo.DefaultNamingContext, 10);
				int currentOU = 1;
				int error = 0;
				using (StreamWriter sw = File.CreateText(filename))
				{
					sw.WriteLine("OU\tstatus");
					foreach (var ou in exploration)
					{
						DisplayAdvancement(" * Exporting OU=" + ou.OU + "(" + currentOU++ + "/" + exploration.Count + ") Type:" + ou.Scope);
						try
						{
							adws.Enumerate(ou.OU, "(objectClass=*)", new string[] { "distinguishedName" }, (ADItem x) => { }, ou.Scope);
							sw.WriteLine(ou.OU + "\tOK");
						}
						catch (DirectoryServicesCOMException ex)
						{
							if (ex.ExtendedError == 234)
							{
								error++;
								Console.ForegroundColor = ConsoleColor.Red;
								DisplayAdvancement("The OU " + ou.OU + " has a problem");
								Console.ResetColor();
								sw.WriteLine(ou.OU + "\tNot OK");
							}
						}
						catch (Exception)
						{
						}
					}
				}
				DisplayAdvancement(error + " error(s) found");
			}

			
		}

		private static void DisplayAdvancement(string data)
		{
			string value = "[" + DateTime.Now.ToLongTimeString() + "] " + data;
			Console.WriteLine(value);
			Trace.WriteLine(value);
		}

	}
}
*/