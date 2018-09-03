//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.ADWS;
using PingCastle.Database;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Text;

namespace PingCastle.Export
{
    public class ExportDataFromActiveDirectoryLive
    {
        string Server;
        int Port;
        NetworkCredential Credential;
        public LiveDataStorage Storage { get; private set; }

        string[] properties = new string[] {
                        "distinguishedName",
                        "name",
                        "objectSid",
                        "nTSecurityDescriptor",
                        "member",
                        "adminCount",
                        "gPLink",
                        "gPCFileSysPath",
                        "scriptPath",
                        "primaryGroupID",
                        "sIDHistory",
            };

        public ExportDataFromActiveDirectoryLive(string server, int port, NetworkCredential credential)
        {
            Server = server;
            Port = port;
            Credential = credential;
            Storage = new LiveDataStorage();
        }

        private void DisplayAdvancement(string data)
        {
            string value = "[" + DateTime.Now.ToLongTimeString() + "] " + data;
            Console.WriteLine(value);
            Trace.WriteLine(value);
        }

		public void ExportData(List<string> UsersToInvestigate)
        {
            ADDomainInfo domainInfo = null;
            RelationFactory relationFactory = null;
            DisplayAdvancement("Getting domain informations");
            using (ADWebService adws = new ADWebService(Server, Port, Credential))
            {
                domainInfo = GetDomainInformation(adws);
                Storage.Initialize(domainInfo);
                Trace.WriteLine("Creating new relation factory");
                relationFactory = new RelationFactory(Storage, domainInfo, Credential);
                DisplayAdvancement("Exporting objects from Active Directory");
				ExportReportData(adws, domainInfo, relationFactory, UsersToInvestigate);

            }
            DisplayAdvancement("Inserting relations between nodes in the database");
            Trace.WriteLine("Inserting relations on hold");
            Storage.InsertRelationOnHold(domainInfo.DnsHostName);
            Trace.WriteLine("Done");
            DisplayAdvancement("Export completed");
        }

        private ADDomainInfo GetDomainInformation(ADWebService adws)
        {
            ADDomainInfo domainInfo = null;
            
            domainInfo = adws.DomainInfo;
            if (adws.useLdap)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("Performance warning: using LDAP instead of ADWS");
                Console.ResetColor();
            }
            // adding the domain sid
            string[] properties = new string[] {"objectSid",
            };
            WorkOnReturnedObjectByADWS callback =
                (ADItem aditem) => 
                { 
                    domainInfo.DomainSid = aditem.ObjectSid;
                };

            adws.Enumerate(domainInfo.DefaultNamingContext,
                                            "(&(objectClass=domain)(distinguishedName=" + domainInfo.DefaultNamingContext + "))",
                                            properties, callback);
            return domainInfo;
        }

        private void ExportReportData(ADWebService adws, ADDomainInfo domainInfo, RelationFactory relationFactory, List<string> UsersToInvestigate)
        {

			List<string> sids = new List<string> {"S-1-5-32-548",
                                        "S-1-5-32-544",
                                        domainInfo.DomainSid.Value + "-512",
                                        domainInfo.DomainSid.Value + "-519",
                                        domainInfo.DomainSid.Value + "-518",
                                        domainInfo.DomainSid.Value + "-500",
                                        "S-1-5-32-551",
                                        domainInfo.DomainSid.Value + "-517", 
                                        "S-1-5-32-569",
                                        domainInfo.DomainSid.Value + "-516",
                                        domainInfo.DomainSid.Value + "-498",
                                        domainInfo.DomainSid.Value + "-520",
                                        "S-1-5-32-557",
                                        domainInfo.DomainSid.Value + "-502",
                                        "S-1-5-32-556",
                                        "S-1-5-32-554",
                                        "S-1-5-32-550",
                                        domainInfo.DomainSid.Value,
                                        domainInfo.DomainSid.Value + "-521",
                                        "S-1-5-32-549",
            };
            ADItem aditem = null;
            foreach (string sid in sids)
            {
                aditem = Search(adws, domainInfo, sid);
				if (aditem != null)
					relationFactory.AnalyzeADObject(aditem);
				else
					Trace.WriteLine("Unable to find the user: " + sid);
            }
			foreach (string user in UsersToInvestigate)
			{
				aditem = Search(adws, domainInfo, user);
				if (aditem != null)
					relationFactory.AnalyzeADObject(aditem);
				else
					Trace.WriteLine("Unable to find the user: " + user);
			}
            
            AnalyzeMissingObjets(adws, domainInfo, relationFactory);
            relationFactory.InsertFiles();
            AnalyzeMissingObjets(adws, domainInfo, relationFactory);

        }

        int AnalyzeMissingObjets(ADWebService adws, ADDomainInfo domainInfo, RelationFactory relationFactory)
        {
            int num = 0;
            while (true)
            {
                List<string> cns = Storage.GetCNToInvestigate();
                if (cns.Count > 0)
                {
                    num += cns.Count;
                    ExportCNData(adws, domainInfo, relationFactory, cns);
                }
                List<string> sids = Storage.GetSIDToInvestigate();
                if (cns.Count == 0 && sids.Count == 0)
                {
                    return num;
                }
                if (sids.Count > 0)
                {
                    num += sids.Count;
                    ExportSIDData(adws, domainInfo, relationFactory, sids);
                }
            }
        }

        private void ExportCNData(ADWebService adws, ADDomainInfo domainInfo, RelationFactory relationFactory, List<string> cns)
        {
            WorkOnReturnedObjectByADWS callback =
                    (ADItem aditem) =>
                    {
                        relationFactory.AnalyzeADObject(aditem);
                    };

            foreach (string cn in cns)
            {
                adws.Enumerate(domainInfo.DefaultNamingContext,
                                                "(distinguishedName=" + ADConnection.EscapeLDAP(cn) + ")",
                                                properties, callback);
            }
        }

        private void ExportSIDData(ADWebService adws, ADDomainInfo domainInfo, RelationFactory relationFactory, List<string> sids)
        {
            WorkOnReturnedObjectByADWS callback =
                    (ADItem aditem) =>
                    {
                        relationFactory.AnalyzeADObject(aditem);
                    };

            foreach (string sid in sids)
            {
                adws.Enumerate(domainInfo.DefaultNamingContext,
												"(objectSid=" + ADConnection.EncodeSidToString(sid) + ")",
                                                properties, callback);
            }
        }

        private ADItem Search(ADWebService adws, ADDomainInfo domainInfo, string userName)
        {
            ADItem output = null;
            WorkOnReturnedObjectByADWS callback =
                    (ADItem aditem) =>
                    {
                        output = aditem;
                    };

            if (userName.StartsWith("S-1-5"))
            {
                adws.Enumerate(domainInfo.DefaultNamingContext,
												"(objectSid=" + ADConnection.EncodeSidToString(userName) + ")",
                                                properties, callback);
            }

            adws.Enumerate(domainInfo.DefaultNamingContext,
											"(&(objectCategory=person)(objectClass=user)(sAMAccountName=" + ADConnection.EscapeLDAP(userName) + "))",
                                            properties, callback);
            if (output != null)
                return output;
            adws.Enumerate(domainInfo.DefaultNamingContext,
											"(cn=" + ADConnection.EscapeLDAP(userName) + ")",
                                            properties, callback);
            if (output != null)
                return output;
            adws.Enumerate(domainInfo.DefaultNamingContext,
											"(displayName=" + ADConnection.EscapeLDAP(userName) + ")",
                                            properties, callback);
            if (output != null)
                return output;
            return output;
        }
    }
}
