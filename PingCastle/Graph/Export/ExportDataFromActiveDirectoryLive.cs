//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.ADWS;
using PingCastle.Data;
using PingCastle.Graph.Database;
using PingCastle.Graph.Reporting;
using PingCastle.misc;
using PingCastle.UserInterface;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Threading;

namespace PingCastle.Graph.Export
{
    public class ExportDataFromActiveDirectoryLive
    {
        List<string> properties = new List<string> {
                        "adminCount",
                        "displayName",
                        "distinguishedName",
                        "dnsHostName",
                        "gPLink",
                        "gPCFileSysPath",
                        "lastLogonTimestamp",
                        "member",
                        "mail",
                        "name",
                        "nTSecurityDescriptor",
                        "objectClass",
                        "objectSid",
                        "primaryGroupID",
                        "pwdlastset",
                        "sAMAccountName",
                        "scriptPath",
                        "servicePrincipalName",
                        "sIDHistory",
                        "userAccountControl",
                        "whencreated",
            };

        public IDataStorage Storage { get; set; }
        private IRelationFactory RelationFactory;
        private ADDomainInfo domainInfo;
        private ADWebService adws;
        private NetworkCredential Credential;
        private readonly IUserInterface _ui = UserInterfaceFactory.GetUserInterface();

        public ExportDataFromActiveDirectoryLive(ADDomainInfo domainInfo, ADWebService adws, NetworkCredential credential)
        {
            this.domainInfo = domainInfo;
            this.adws = adws;
            Credential = credential;
            Storage = new LiveDataStorage();
        }

        private void DisplayAdvancement(string data)
        {
            string value = "[" + DateTime.Now.ToLongTimeString() + "] " + data;
            _ui.DisplayMessage(value);
            Trace.WriteLine(value);
        }

        public GraphObjectReference ExportData(List<string> UsersToInvestigate)
        {

            GraphObjectReference objectReference = null;
            DisplayAdvancement("- Initialize");
            Storage.Initialize(domainInfo, adws);
            Trace.WriteLine("- Creating new relation factory");
            RelationFactory = new RelationFactory(Storage, domainInfo, adws);
            RelationFactory.Initialize(adws);
            DisplayAdvancement("- Searching for critical and infrastructure objects");
            objectReference = new GraphObjectReference(domainInfo);
            AddDnsAdmins(objectReference);
            BuildDirectDelegationData();

            ExportReportData(objectReference, UsersToInvestigate);
            DisplayAdvancement("- Completing object collection");
            Trace.WriteLine("Inserting relations on hold");
            Storage.InsertRelationOnHold();
            Trace.WriteLine("Done");
            DisplayAdvancement("- Export completed");
            DumpObjectReferenceOnTrace();
            return objectReference;
        }

        private void AddDnsAdmins(GraphObjectReference objectReference)
        {
            string[] properties = new string[] {
                        "name",
                        "objectSid"
            };
            bool dnsAdminFound = false;
            WorkOnReturnedObjectByADWS callback =
                (ADItem x) =>
                {
                    objectReference.Objects[CompromiseGraphDataTypology.PrivilegedAccount].Add(new GraphSingleObject(x.ObjectSid.Value, GraphObjectReference.DnsAdministrators, CompromiseGraphDataObjectRisk.Medium));
                    dnsAdminFound = true;
                };
            try
            {
                // we do a one level search just case the group is in the default position
                adws.Enumerate("CN=Users," + domainInfo.DefaultNamingContext, "(&(objectClass=group)(description=DNS Administrators Group))", properties, callback, "OneLevel");
                if (!dnsAdminFound)
                {
                    adws.Enumerate("CN=Users," + domainInfo.DefaultNamingContext, "(&(objectClass=group)(sAMAccountName=DNSAdmins))", properties, callback, "OneLevel");
                }
            }
            catch(Exception)
            {
                // trap silently the exception if the users container has been removed
            }
            if (!dnsAdminFound)
            {
                // then full tree. This is an optimization for LDAP request
                adws.Enumerate(domainInfo.DefaultNamingContext, "(&(objectClass=group)(description=DNS Administrators Group))", properties, callback);
            }
            if (!dnsAdminFound)
            {
                adws.Enumerate(domainInfo.DefaultNamingContext, "(&(objectClass=group)(sAMAccountName=DNSAdmins))", properties, callback);
            }
        }

        private void DumpObjectReferenceOnTrace()
        {
            Trace.WriteLine("============================");
            Trace.WriteLine("Dump graph");
            Trace.WriteLine("============================");
            var s = (LiveDataStorage)Storage;
            foreach (var id in s.nodes.Keys)
            {
                var node = s.nodes[id];
                if (s.relations.ContainsKey(id))
                {
                    var relations = s.relations[id];
                    foreach (var rid in relations.Keys)
                    {
                        Trace.WriteLine(node.Name + " -> " + s.nodes[rid].Name + " [" + string.Join(",", relations[rid].Hint.ToArray()) + "]");
                    }
                }
                else
                {
                    Trace.WriteLine(node.Name + " -> <ALONE>");
                }
            }
            Trace.WriteLine("============================");
        }

        private void BuildDirectDelegationData()
        {
            if (domainInfo.ForestFunctionality < 2)
                return;
            var map = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            var protocolTransitionSid = new List<string>();
            WorkOnReturnedObjectByADWS callback =
                    (ADItem aditem) =>
                    {
                        foreach (var d in aditem.msDSAllowedToDelegateTo)
                        {
                            var spn = d.Split('/');
                            if (spn.Length < 2)
                                continue;
                            if (!map.ContainsKey(spn[1]))
                                map[spn[1]] = new List<string>();
                            var sid = aditem.ObjectSid.Value;
                            if (!map[spn[1]].Contains(sid))
                                map[spn[1]].Add(sid);
                        }
                        if ((aditem.UserAccountControl & 0x1000000) != 0)
                        {
                            protocolTransitionSid.Add(aditem.ObjectSid.Value);
                        }
                    };
            adws.Enumerate(domainInfo.DefaultNamingContext,
                                                "(&(msDS-AllowedToDelegateTo=*)((userAccountControl:1.2.840.113556.1.4.804:=16777216)))",
                                                new string[] { "objectSid", "msDS-AllowedToDelegateTo", "userAccountControl" }, callback);
            RelationFactory.InitializeDelegation(map, protocolTransitionSid);
        }

        private void ExportReportData(GraphObjectReference objectReference, List<string> UsersToInvestigate)
        {
            List<ADItem> aditems = null;
            foreach (var typology in objectReference.Objects.Keys)
            {
                var toDelete = new List<GraphSingleObject>();
                foreach (var obj in objectReference.Objects[typology])
                {
                    Trace.WriteLine("Working on " + obj.Description);
                    aditems = Search(obj.Name);
                    if (aditems.Count != 0)
                        RelationFactory.AnalyzeADObject(aditems[0]);
                    else
                    {
                        Trace.WriteLine("Unable to find the user: " + obj.Description);
                        toDelete.Add(obj);
                    }
                }
                foreach (var obj in toDelete)
                {
                    objectReference.Objects[typology].Remove(obj);
                }
            }
            if (UsersToInvestigate != null)
            {
                foreach (string user in UsersToInvestigate)
                {
                    Trace.WriteLine("Working on " + user);
                    aditems = Search(user);
                    if (aditems.Count != 0)
                    {
                        string userKey = user;
                        if (aditems[0].ObjectSid != null)
                        {
                            userKey = aditems[0].ObjectSid.Value;
                        }
                        objectReference.Objects[Data.CompromiseGraphDataTypology.UserDefined].Add(new GraphSingleObject(userKey, user));
                        RelationFactory.AnalyzeADObject(aditems[0]);
                    }
                    else
                    {
                        Trace.WriteLine("Unable to find the user: " + user);
                    }
                }
            }
            foreach (var item in objectReference.TechnicalObjects)
            {
                aditems = Search(item);
                if (aditems.Count != 0)
                    RelationFactory.AnalyzeADObject(aditems[0]);
            }
            AnalyzeMissingObjets();
        }

        void AnalyzeMissingObjets()
        {
            int step = 1;
            while (true)
            {
                int num = 0;
                DisplayAdvancement("- Collecting objects - Iteration " + step++);
                foreach (SearchType searchType in Enum.GetValues(typeof(SearchType)))
                {
                    List<string> items = Storage.GetMissingItem(searchType);
                    if (items != null && items.Count > 0)
                    {
                        num += items.Count;
                        foreach (var aditem in GetRemainingData(items, searchType))
                        {
                            RelationFactory.AnalyzeADObject(aditem);
                        }
                    }
                }
                List<string> files = Storage.GetFilesToInvestigate();
                if (files.Count > 0)
                {
                    num += files.Count;
                    ExportFilesData(files, false);
                }
                List<string> gpo = Storage.GetGPOToInvestigate();
                if (gpo.Count > 0)
                {
                    num += gpo.Count;
                    ExportFilesData(gpo, true);
                }
                if (num == 0)
                {
                    return;
                }
            }
        }

        private List<ADItem> GetRemainingData(List<string> itemList, SearchType searchType)
        {
            var output = new List<ADItem>();
            foreach (string item in itemList)
            {
                var aditem = Search(item, searchType);
                if (aditem.Count > 0)
                    output.AddRange(aditem);
            }
            return output;
        }

        private void ExportFilesData(List<string> files, bool isGPO)
        {
            ExportFilesDataWithImpersonation(files, isGPO);            
        }

        private void ExportFilesDataWithImpersonation(List<string> files, bool isGPO)
        {
            // insert relation related to the files already seen.
            // add subdirectory / sub file is the permission is not inherited
            BlockingQueue<string> queue = new BlockingQueue<string>(200);
            int numberOfThread = 20;
            Thread[] threads = new Thread[numberOfThread];
            try
            {
                ThreadStart threadFunction = () =>
                {
                    adws.ThreadInitialization();
                    for (; ; )
                    {
                        string fileName = null;
                        if (!queue.Dequeue(out fileName)) break;

                        // function is safe and will never trigger an exception
                        if (isGPO)
                            RelationFactory.AnalyzeGPO(fileName);
                        else
                            RelationFactory.AnalyzeFile(fileName);

                    }
                    Trace.WriteLine("Consumer quitting");
                };

                // Consumers
                for (int i = 0; i < numberOfThread; i++)
                {
                    threads[i] = new Thread(threadFunction);
                    threads[i].Start();
                }

                // do it in parallele (else time *6 !)
                foreach (string file in files)
                {
                    queue.Enqueue(file);
                }
                queue.Quit();
                Trace.WriteLine("insert file completed. Waiting for worker thread to complete");
                for (int i = 0; i < numberOfThread; i++)
                {
                    threads[i].Join();
                }
                Trace.WriteLine("Done insert file");
            }
            finally
            {

                queue.Quit();
                for (int i = 0; i < numberOfThread; i++)
                {
                    if (threads[i] != null)
                        if (threads[i].ThreadState == System.Threading.ThreadState.Running)
                            threads[i].Abort();
                }
            }
        }

        private List<ADItem> Search(string userName, SearchType search = SearchType.Unknown)
        {
            List<ADItem> output = new List<ADItem>();
            string searchString = null;
            string namingContext = domainInfo.DefaultNamingContext;
            switch (search)
            {
                default:
                case SearchType.Unknown:
                    if (userName.StartsWith("S-1-5"))
                    {
                        output = Search(userName, SearchType.Sid);
                        if (output != null)
                            return output;
                    }
                    if (userName.StartsWith("CN=") && userName.EndsWith(domainInfo.DefaultNamingContext))
                    {
                        output = Search(userName, SearchType.DistinguishedName);
                        if (output != null)
                            return output;
                    }
                    if (userName.Length <= 20)
                    {
                        output = Search(userName, SearchType.SAMAccountName);
                        if (output != null)
                            return output;
                    }
                    output = Search(userName, SearchType.Name);
                    if (output != null)
                        return output;
                    output = Search(userName, SearchType.DisplayName);
                    if (output != null)
                        return output;
                    return null;
                case SearchType.Sid:
                    searchString = "(|(objectSid=" + ADConnection.EncodeSidToString(userName) + ")(sidhistory=" + ADConnection.EncodeSidToString(userName) + "))";
                    break;
                case SearchType.DistinguishedName:
                    searchString = "(distinguishedName=" + ADConnection.EscapeLDAP(userName) + ")";
                    if (userName.EndsWith(domainInfo.ConfigurationNamingContext, StringComparison.InvariantCultureIgnoreCase))
                    {
                        namingContext = domainInfo.ConfigurationNamingContext;
                    }
                    else if (userName.EndsWith(domainInfo.SchemaNamingContext, StringComparison.InvariantCultureIgnoreCase))
                    {
                        namingContext = domainInfo.SchemaNamingContext;
                    }
                    break;
                case SearchType.SAMAccountName:
                    searchString = "(&(objectCategory=person)(objectClass=user)(sAMAccountName=" + ADConnection.EscapeLDAP(userName) + "))";
                    break;
                case SearchType.Name:
                    searchString = "(cn=" + ADConnection.EscapeLDAP(userName) + ")";
                    break;
                case SearchType.DisplayName:
                    searchString = "(displayName=" + ADConnection.EscapeLDAP(userName) + ")";
                    break;
                case SearchType.PrimaryGroupId:
                    searchString = "(primaryGroupID=" + userName + ")";
                    break;
            }
            WorkOnReturnedObjectByADWS callback =
                    (ADItem aditem) =>
                    {
                        output.Add(aditem);
                    };
            adws.Enumerate(namingContext,
                                                searchString,
                                                properties.ToArray(), callback);
            return output;
        }
    }
}
