//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
/*
using PingCastle.ADWS;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text;

namespace PingCastle.Scanners
{
    public class ReplicationScanner : IScanner
    {
        public string Name { get { return "replication";}}
		public string Description { get { return "Search replication metadata for modification done in the past but recorded more than 1 day after the supposed modification"; } }

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


			List<string> reference = new List<string>();
            ADDomainInfo domainInfo = null;
			Dictionary<uint, string> attReference = null;
			DisplayAdvancement("Starting");
            using (FileStream fsRepl = File.Create(filename + ".replData"))
            using (StreamWriter swRepl = new StreamWriter(fsRepl))
            using (ADWebService adws = new ADWebService(Server, Port, Credential))

            {
                domainInfo = adws.DomainInfo;

				DisplayAdvancement("Connected");

				attReference = BuildAllAttributeDictionnary(adws);

                string[] properties = new string[] { "distinguishedName", "replPropertyMetaData" };

                int id = 0;
                WorkOnReturnedObjectByADWS callback =
                    (ADItem x) =>
                    {
						if (String.IsNullOrEmpty(x.DistinguishedName) || x.ReplPropertyMetaData == null)
							return;
                        reference.Add(x.DistinguishedName);
                        foreach (var attId in x.ReplPropertyMetaData.Keys)
                        {
                            var usn = x.ReplPropertyMetaData[attId].UsnLocalChange;
                            var date = x.ReplPropertyMetaData[attId].LastOriginatingChange;

                            swRepl.WriteLine("{0:X8},{1:X8},{2:X8},{3:X16}", usn, id, attId, date.ToFileTime());
                        }
						id++;
						if (id % 1000 == 0)
						{
							DisplayAdvancement(id + " objects enumerated");
						}
                    };

				adws.Enumerate(domainInfo.DefaultNamingContext, "(objectClass=*)", properties, callback, "Subtree");
            }

			DisplayAdvancement("All objects enumerated");
			DisplayAdvancement("Sorting data");
			Process process = new Process();
			// Configure the process using the StartInfo properties.
			process.StartInfo.FileName = "sort.exe";
			process.StartInfo.Arguments = filename + ".replData /o " + filename + ".replData2";
			process.StartInfo.WindowStyle = ProcessWindowStyle.Maximized;
			process.Start();
			process.WaitForExit();// Waits here for the process to exit.
			DisplayAdvancement("data sorted");
			File.Delete(filename + ".replData");

			int l = 0;
			DateTime refDate = DateTime.MinValue;
			using (StreamWriter sw = File.CreateText(filename))
			using (var sr = new StreamReader(filename + ".replData2"))
			{
				sw.WriteLine("PreviousUsn,PreviousObject,PreviousAttribute,PreviousDate,NewUsn,NewObject,NewAttribute,NewDate");
				string previousLine = null;
				while (!sr.EndOfStream)
				{
					string line = sr.ReadLine();
					var elt = line.Split(',');
					int usn = Convert.ToInt32(elt[0], 16);
					int id = Convert.ToInt32(elt[1], 16);
					uint attId = Convert.ToUInt32(elt[2], 16);
					DateTime date = DateTime.FromFileTime(Convert.ToInt64(elt[3], 16));
					if (l != 0 && refDate.AddDays(-7) > date)
					{
						string obj = reference[id];
						string attribute = "unknown(" + attId + ")";
						if (attReference.ContainsKey(attId))
							attribute = attReference[attId];
						var previousElt = previousLine.Split(',');
						uint previousAttId = Convert.ToUInt32(previousElt[2], 16);
						string Previousattribute = "unknown(" + previousAttId + ")";
						if (attReference.ContainsKey(previousAttId))
							Previousattribute = attReference[previousAttId];
						int previousUsn = Convert.ToInt32(previousElt[0], 16);
						DateTime previousDate = DateTime.FromFileTime(Convert.ToInt64(previousElt[3], 16));
						sw.WriteLine(previousUsn + "," + reference[Convert.ToInt32(previousElt[1], 16)] + "," + Previousattribute + "," + previousDate.ToString("u") + "," + usn + "," + obj + "," + attribute + "," + date.ToString("u"));
					}
					refDate = date;
					l++;
					previousLine = line;
				}
			}
			File.Delete(filename + ".replData2");
        }

		private Dictionary<uint, string> BuildAllAttributeDictionnary(ADWebService adws)
		{
			var output = new Dictionary<uint, string>();
			string[] properties = new string[] { "lDAPDisplayName", "attributeID" };

			WorkOnReturnedObjectByADWS callback =
				(ADItem x) =>
				{
					output[TransformOidToAttId(x.AttributeID, x.lDAPDisplayName)] = x.lDAPDisplayName;
				};

			adws.Enumerate(adws.DomainInfo.SchemaNamingContext, "(&(objectclass=attributeSchema)(lDAPDisplayName=*))", properties, callback, "Subtree");
			return output;
		}

		private uint TransformOidToAttId(string attributeId, string name)
		{
			uint attId = 0;
			int pos = attributeId.LastIndexOf('.');
			string prefix = attributeId.Substring(0, pos);
			string lastDigit = attributeId.Substring(pos + 1);
			switch (prefix)
			{
				case "2.5.4":
					attId = 0;
					break;
				case "2.5.6":
					attId = 1;
					break;
				case "1.2.840.113556.1.2":
					attId = 2;
					break;
				case "1.2.840.113556.1.3":
					attId = 3;
					break;
				case "2.16.840.1.101.2.2.1":
					attId = 4;
					break;
				case "2.16.840.1.101.2.2.3":
					attId = 5;
					break;
				case "2.16.840.1.101.2.1.5":
					attId = 6;
					break;
				case "2.16.840.1.101.2.1.4":
					attId = 7;
					break;
				case "2.5.5":
					attId = 8;
					break;
				case "1.2.840.113556.1.4":
					attId = 9;
					break;
				case "1.2.840.113556.1.5":
					attId = 10;
					break;
				case "1.2.840.113556.1.4.260":
					attId = 11;
					break;
				case "1.2.840.113556.1.5.56":
					attId = 12;
					break;
				case "1.2.840.113556.1.4.262":
					attId = 13;
					break;
				case "1.2.840.113556.1.5.57":
					attId = 14;
					break;
				case "1.2.840.113556.1.4.263":
					attId = 15;
					break;
				case "1.2.840.113556.1.5.58":
					attId = 16;
					break;
				case "1.2.840.113556.1.5.73":
					attId = 17;
					break;
				case "1.2.840.113556.1.4.305":
					attId = 18;
					break;
				case "0.9.2342.19200300.100":
					attId = 19;
					break;
				case "2.16.840.1.113730.3":
					attId = 20;
					break;
				case "0.9.2342.19200300.100.1":
					attId = 21;
					break;
				case "2.16.840.1.113730.3.1":
					attId = 22;
					break;
				case "1.2.840.113556.1.5.7000":
					attId = 23;
					break;
				case "2.5.21":
					attId = 24;
					break;
				case "2.5.18":
					attId = 25;
					break;
				case "2.5.20":
					attId = 26;
					break;
				case "1.3.6.1.4.1.1466.101.119":
					attId = 27;
					break;
				case "2.16.840.1.113730.3.2":
					attId = 28;
					break;
				case "1.3.6.1.4.1.250.1":
					attId = 29;
					break;
				case "1.2.840.113549.1.9":
					attId = 30;
					break;
				case "0.9.2342.19200300.100.4":
					attId = 31;
					break;
				case "1.2.840.113556.1.6.23":
					attId = 32;
					break;
				case "1.2.840.113556.1.6.18.1":
					attId = 33;
					break;
				case "1.2.840.113556.1.6.18.2":
					attId = 34;
					break;
				case "1.2.840.113556.1.6.13.3":
					attId = 35;
					break;
				case "1.2.840.113556.1.6.13.4":
					attId = 36;
					break;
				case "1.3.6.1.1.1.1":
					attId = 37;
					break;
				case "1.3.6.1.1.1.2":
					attId = 38;
					break;
					
				default:
					Trace.WriteLine("attribute from a table unknown " + attributeId + " " + name);
					return 0xFFFFFFFF;
			}
			attId = (attId * 0x10000) + Convert.ToUInt32(lastDigit);
			return attId;
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
