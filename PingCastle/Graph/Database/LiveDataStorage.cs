//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.ADWS;
using PingCastle.Graph.Reporting;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection;
using System.Security.Principal;
using System.Text.RegularExpressions;

namespace PingCastle.Graph.Database
{
    public struct DataStorageDomainTrusts
    {
        public string NetbiosDomainName;
        public string DnsDomainName;
        public uint Flags;
        public uint ParentIndex;
        public uint TrustType;
        public uint TrustAttributes;
        public SecurityIdentifier DomainSid;
        public Guid DomainGuid;
    }


    public enum SearchType
    {
        Unknown,
        Sid,
        DistinguishedName,
        SAMAccountName,
        Name,
        DisplayName,
        PrimaryGroupId,
    }


    public interface IDataStorage
    {
        // TODO - to be removed
        // used to store various information about the domain in general (its FQDN, its SID, ...)
        Dictionary<string, string> GetDatabaseInformation();

        // used to locate an item based on its name
        int SearchItem(string name);
        // once, the ID located by the previous function, return the node
        Node RetrieveNode(int id);
        // generated lookup function
        Dictionary<int, Node> RetrieveNodes(ICollection<int> nodes);
        // based on a node list, return all path to other nodes (at the exclusion of the knownId ones)
        ICollection<Relation> SearchRelations(ICollection<int> SourceIds, ICollection<int> knownIds);

        // create a node
        int InsertNode(ADItem adItem);
        int InsertUnknowNode(string name);
        int InsertFileNode(string name);
        int InsertFileNode(string name, string description);
        int InsertGPONode(string name);
        // create a link between 2 nodes
        void InsertRelation(string mappingMaster, MappingType typeMaster, string mappingSlave, MappingType typeSlave, RelationType relationType);

        List<DataStorageDomainTrusts> GetKnownDomains();

        // used to retrieve objects in queue and not examined
        List<string> GetMissingItem(SearchType searchType);
        List<string> GetFilesToInvestigate();
        List<string> GetGPOToInvestigate();

        void Initialize(ADDomainInfo domainInfo, IADConnection adws);

        void InsertRelationOnHold();

    }

    public class LiveDataStorage : IDataStorage
    {
        public Dictionary<int, Node> nodes;
        public Dictionary<string, Node> nodesBySID;
        public Dictionary<string, Node> nodesByDN;
        public Dictionary<string, Node> nodesByFilename;
        public Dictionary<string, Node> nodesGPOByFilename;
        int index;
        // first index = slave ; second index = master
        public Dictionary<int, Dictionary<int, Relation>> relations;
        public Dictionary<string, string> databaseInformation;

        public List<int> KnownPGId = new List<int>() { 513, 515 };
        public List<string> CNToInvestigate { get; private set; }
        public List<string> SIDToInvestigate { get; private set; }
        public List<int> PGIdToInvestigate { get; private set; }
        public List<string> FilesToInvestigate { get; private set; }
        public List<string> GPOToInvestigate { get; private set; }
        public List<DataStorageDomainTrusts> KnownDomains { get; private set; }
        private IADConnection adws;

        struct RelationOnHold
        {
            public string mappingMaster;
            public MappingType typeMaster;
            public string mappingSlave;
            public MappingType typeSlave;
            public RelationType relationType;
        }
        List<RelationOnHold> relationsOnHold;

        public LiveDataStorage()
        {
            nodes = new Dictionary<int, Node>();
            nodesBySID = new Dictionary<string, Node>();
            nodesByDN = new Dictionary<string, Node>();
            nodesByFilename = new Dictionary<string, Node>();
            nodesGPOByFilename = new Dictionary<string, Node>();
            index = 0;
            relations = new Dictionary<int, Dictionary<int, Relation>>();
            relationsOnHold = new List<RelationOnHold>();
            databaseInformation = new Dictionary<string, string>();
            SIDToInvestigate = new List<string>();
            CNToInvestigate = new List<string>();
            PGIdToInvestigate = new List<int>();
            FilesToInvestigate = new List<string>();
            GPOToInvestigate = new List<string>();
            KnownDomains = new List<DataStorageDomainTrusts>();
        }

        public void Initialize(ADDomainInfo domainInfo, IADConnection adws)
        {
            databaseInformation["EngineVersion"] = Assembly.GetExecutingAssembly().GetName().Version.ToString();
            databaseInformation["Date"] = DateTime.Now.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss");
            databaseInformation["DomainName"] = domainInfo.DomainName;
            databaseInformation["DefaultNamingContext"] = domainInfo.DefaultNamingContext;
            databaseInformation["DomainSid"] = domainInfo.DomainSid.Value;
            databaseInformation["DomainNetBIOS"] = domainInfo.NetBIOSName;
            this.adws = adws;
        }

        public List<string> GetMissingItem(SearchType searchType)
        {
            List<string> output = new List<string>();
            switch (searchType)
            {
                default:
                    return null;
                case SearchType.DistinguishedName:
                    output.AddRange(CNToInvestigate);
                    CNToInvestigate.Clear();
                    return output;
                case SearchType.Sid:
                    output.AddRange(SIDToInvestigate);
                    SIDToInvestigate.Clear();
                    return output;
                case SearchType.PrimaryGroupId:
                    output.AddRange(PGIdToInvestigate.ConvertAll(x => x.ToString()));
                    KnownPGId.AddRange(PGIdToInvestigate);
                    PGIdToInvestigate.Clear();
                    return output;

            }
        }

        public List<string> GetFilesToInvestigate()
        {
            List<string> output = new List<string>();
            output.AddRange(FilesToInvestigate);
            FilesToInvestigate.Clear();
            return output;
        }

        public List<string> GetGPOToInvestigate()
        {
            List<string> output = new List<string>();
            output.AddRange(GPOToInvestigate);
            GPOToInvestigate.Clear();
            return output;
        }

        public int InsertUnknowNode(string name)
        {
            if (string.IsNullOrEmpty(name))
                return -1;
            if (name.Contains(",CN=ForeignSecurityPrincipals,DC="))
            {
                return InsertUnknownSidNode(name.Substring(3, name.IndexOf(',') - 3), name);
            }
            Node node = new Node();
            node.Type = "unknown";
            node.Dn = name;
            {
                Regex re = new Regex(@"^(?:OU|CN)=(?<cn>.+?)(?<!\\),(?<ou>(?:(?:OU|CN).+?(?<!\\),)*(?<dc>DC.+?))$");
                Match m = re.Match(name);
                if (!m.Success)
                    node.Shortname = "<none>";
                else
                    node.Shortname = m.Groups[1].Value;
            }
            return CreateNode(node);
        }

        public int InsertFileNode(string name)
        {
            return InsertFileNode(name, null);
        }
        public int InsertFileNode(string name, string description)
        {
            Node node = new Node();
            node.Type = "file";
            int start = 0;
            if (string.IsNullOrEmpty(description))
            {
                if (!string.IsNullOrEmpty(name))
                {
                    start = name.LastIndexOf('\\');
                    if (start == -1)
                        start = 0;
                    else
                        start++;
                    node.Shortname = name.Substring(start);
                }
            }
            else
            {
                node.Shortname = description;
            }
            node.FileName = name;
            return CreateNode(node);
        }

        public int InsertGPONode(string name)
        {
            Node node = new Node();
            node.Type = "gpodirectory";
            int start = 0;
            if (!string.IsNullOrEmpty(name))
            {
                start = name.LastIndexOf('\\');
                if (start == -1)
                    start = 0;
                else
                    start++;
                node.Shortname = name.Substring(start);
            }
            node.FileName = name;
            return CreateNode(node);
        }

        public int InsertUnknownSidNode(string Sid, string Dn = null)
        {
            string referencedDomain = null;
            string ntaccount = null;
            bool EveryoneLikeGroup = false;
            switch (Sid)
            {
                // avoid CREATOR OWNER (used for dynamic permissions)
                case "S-1-3-0":
                    return -1;
                // avoid NT AUTHORITY\SELF
                case "S-1-5-10":
                    return -1;
                case "S-1-5-7":
                    ntaccount = GraphObjectReference.Anonymous;
                    EveryoneLikeGroup = true;
                    break;
                // SYSTEM
                case "S-1-5-18":
                    return -1;
                case "S-1-5-11":
                    ntaccount = GraphObjectReference.AuthenticatedUsers;
                    EveryoneLikeGroup = true;
                    break;
                case "S-1-1-0":
                    ntaccount = GraphObjectReference.Everyone;
                    EveryoneLikeGroup = true;
                    break;
                case "S-1-5-32-545":
                    ntaccount = GraphObjectReference.Users;
                    EveryoneLikeGroup = true;
                    break;
                default:
                    if (Sid.EndsWith("-513") || Sid.EndsWith("-515"))
                    {
                        EveryoneLikeGroup = true;
                    }
                    if (Sid.Contains("\0"))
                        Sid = Sid.Split('\0')[0];
                    ntaccount = adws.ConvertSIDToName(Sid, out referencedDomain);
                    if (ntaccount == Sid)
                    {
                        if (string.IsNullOrEmpty(referencedDomain))
                            ntaccount = Sid;
                        else
                            ntaccount = referencedDomain + "\\" + Sid;
                    }
                    break;
            }
            Node node = new Node();
            node.Type = "foreignsecurityprincipal";
            node.Shortname = ntaccount;
            node.Sid = Sid;
            node.Dn = node.Sid;
            node.EveryoneLikeGroup = EveryoneLikeGroup;
            node.Dn = Dn;
            return CreateNode(node);
        }

        public int InsertNode(ADItem aditem)
        {
            if (string.Equals(aditem.Class, "foreignsecurityprincipal", StringComparison.OrdinalIgnoreCase) && aditem.ObjectSid != null)
            {
                return InsertUnknownSidNode(aditem.ObjectSid.Value);
            }
            Node node = new Node();
            node.Type = aditem.Class.ToLowerInvariant();
            node.Dn = aditem.DistinguishedName;
            node.Sid = (aditem.ObjectSid != null ? aditem.ObjectSid.Value : null);
            if (!string.IsNullOrEmpty(node.Sid) && (node.Sid.EndsWith("-513") || node.Sid.EndsWith("-515")))
            {
                node.EveryoneLikeGroup = true;
            }
            node.Shortname = aditem.DisplayName;
            node.ADItem = aditem;
            // reentrance from previous if
            if (string.IsNullOrEmpty(node.Shortname))
            {
                node.Shortname = aditem.Name;
            }
            if (string.IsNullOrEmpty(node.Shortname))
            {
                Regex re = new Regex(@"^(?:OU|CN)=(?<cn>.+?)(?<!\\),(?<ou>(?:(?:OU|CN).+?(?<!\\),)*(?<dc>DC.+?))$");
                Match m = re.Match(aditem.DistinguishedName);
                if (!m.Success)
                    node.Shortname = "<none>";
                else
                    node.Shortname = m.Groups[1].Value;
            }
            if (string.Equals(node.Type, "unknown", StringComparison.OrdinalIgnoreCase))
            {
                if (node.Dn.Contains(",CN=ForeignSecurityPrincipals,DC="))
                {
                    node.Type = "foreignsecurityprincipal";
                    node.Sid = node.Dn.Substring(3, node.Dn.IndexOf(',') - 3);
                    if (node.Sid.Contains("\0"))
                        node.Sid = node.Sid.Split('\0')[0];
                }
            }
            return CreateNode(node);

        }

        int CreateNode(Node node)
        {
            //locking is important because this function can be called by threads (analysing GPO, ...)
            lock (nodes)
            {
                Trace.WriteLine("Inserting node " + index + " name=" + node.Name + " sid=" + node.Sid + " shortname=" + node.Shortname);
                // defensive programming checks
                if (!string.IsNullOrEmpty(node.Dn) && nodesByDN.ContainsKey(node.Dn.ToLowerInvariant()))
                {
                    Trace.WriteLine("DN already present");
                    return nodesByDN[node.Dn.ToLowerInvariant()].Id;
                }
                if (!string.IsNullOrEmpty(node.Sid) && nodesBySID.ContainsKey(node.Sid.ToLowerInvariant()))
                {
                    Trace.WriteLine("SID already present");
                    return nodesBySID[node.Sid.ToLowerInvariant()].Id;
                }
                if (!string.IsNullOrEmpty(node.FileName) && node.Type != "gpodirectory" && (nodesByFilename.ContainsKey(node.FileName.ToLowerInvariant())))
                {
                    Trace.WriteLine("FileName already present");
                    return nodesByFilename[node.FileName.ToLowerInvariant()].Id;
                }
                if (!string.IsNullOrEmpty(node.FileName) && node.Type == "gpodirectory" && (nodesGPOByFilename.ContainsKey(node.FileName.ToLowerInvariant())))
                {
                    Trace.WriteLine("FileName already present");
                    return nodesGPOByFilename[node.FileName.ToLowerInvariant()].Id;
                }

                // inserting the node
                node.Id = index;
                nodes.Add(index, node);
                if (!string.IsNullOrEmpty(node.FileName))
                {
                    if (node.FileName.StartsWith("\\\\"))
                    {
                        if (node.Type != "gpodirectory")
                        {
                            nodesByFilename.Add(node.FileName.ToLowerInvariant(), node);
                            if (FilesToInvestigate.Contains(node.FileName.ToLowerInvariant()))
                                FilesToInvestigate.Remove(node.FileName.ToLowerInvariant());
                        }
                        else
                        {
                            nodesGPOByFilename.Add(node.FileName.ToLowerInvariant(), node);
                            if (GPOToInvestigate.Contains(node.FileName.ToLowerInvariant()))
                                GPOToInvestigate.Remove(node.FileName.ToLowerInvariant());
                        }
                    }
                }
                if (!string.IsNullOrEmpty(node.Dn))
                {
                    nodesByDN.Add(node.Dn.ToLowerInvariant(), node);
                    if (CNToInvestigate.Contains(node.Dn.ToLowerInvariant()))
                        CNToInvestigate.Remove(node.Dn.ToLowerInvariant());
                }
                if (!string.IsNullOrEmpty(node.Sid))
                {
                    nodesBySID.Add(node.Sid.ToLowerInvariant(), node);
                    if (SIDToInvestigate.Contains(node.Sid.ToUpperInvariant()))
                        SIDToInvestigate.Remove(node.Sid.ToUpperInvariant());
                    // handle primary group id
                    if (node.Type == "group")
                    {
                        if (node.Sid.StartsWith("S-1-5-21-"))
                        {
                            var part = node.Sid.Split('-');
                            int PGId = int.Parse(part[part.Length - 1]);
                            if (!KnownPGId.Contains(PGId) && !PGIdToInvestigate.Contains(PGId))
                            {
                                PGIdToInvestigate.Add(PGId);
                            }
                        }
                    }
                }
                return index++;
            }
        }

        public void InsertRelation(string mappingMaster, MappingType typeMaster, string mappingSlave, MappingType typeSlave, RelationType relationType)
        {
            Trace.WriteLine("Stack:" + mappingMaster + "," + typeMaster.ToString() + "," + mappingSlave + "," + typeSlave + "," + relationType.ToString());
            RelationOnHold relation = new RelationOnHold();
            relation.mappingMaster = mappingMaster;
            relation.typeMaster = typeMaster;
            relation.mappingSlave = mappingSlave;
            relation.typeSlave = typeSlave;
            relation.relationType = relationType;
            AddDataToInvestigate(mappingMaster, typeMaster);
            AddDataToInvestigate(mappingSlave, typeSlave);
            relationsOnHold.Add(relation);
        }

        void AddDataToInvestigate(string mapping, MappingType type)
        {
            // avoid dealing with files
            if (string.IsNullOrEmpty(mapping))
            {
                Trace.WriteLine("Ignoring addition of mapping " + mapping + "type = " + type);
                return;
            }
            else
            {
                switch (type)
                {
                    case MappingType.DistinguishedName:
                        if (!nodesByDN.ContainsKey(mapping.ToLowerInvariant()))
                            if (!CNToInvestigate.Contains(mapping.ToLowerInvariant()))
                                CNToInvestigate.Add(mapping.ToLowerInvariant());
                        break;
                    case MappingType.Sid:
                        if (mapping.StartsWith("S-1-5-32-", StringComparison.InvariantCultureIgnoreCase) || mapping.StartsWith(databaseInformation["DomainSid"]))
                            if (!nodesBySID.ContainsKey(mapping.ToLowerInvariant()))
                                if (!SIDToInvestigate.Contains(mapping.ToUpperInvariant()))
                                    SIDToInvestigate.Add(mapping.ToUpperInvariant());
                        break;
                    case MappingType.FileName:
                        if (mapping.StartsWith("\\\\"))
                        {
                            if (!nodesByFilename.ContainsKey(mapping.ToLowerInvariant()))
                                if (!FilesToInvestigate.Contains(mapping.ToLowerInvariant()))
                                    FilesToInvestigate.Add(mapping.ToLowerInvariant());
                        }
                        break;
                    case MappingType.GPODirectory:
                        if (mapping.StartsWith("\\\\"))
                        {
                            if (!nodesGPOByFilename.ContainsKey(mapping.ToLowerInvariant()))
                                if (!GPOToInvestigate.Contains(mapping.ToLowerInvariant()))
                                    GPOToInvestigate.Add(mapping.ToLowerInvariant());
                        }
                        break;
                }
            }
        }

        public void InsertRelationOnHold()
        {
            foreach (RelationOnHold relation in relationsOnHold)
            {
                try
                {
                    InsertRelationInternal(relation.mappingMaster, relation.typeMaster, relation.mappingSlave, relation.typeSlave, relation.relationType);
                }
                catch (Exception)
                {
                    Trace.WriteLine("An exception occured when working on : {" + relation.mappingMaster + "," + relation.typeMaster + "," + relation.mappingSlave + "," + relation.typeSlave + "," + relation.relationType + "}");
                    throw;
                }
            }
            relationsOnHold.Clear();
        }

        private void InsertRelationInternal(string mappingMaster, MappingType typeMaster, string mappingSlave, MappingType typeSlave, RelationType relationType)
        {
            int masteridx = GetIdx(mappingMaster, typeMaster);
            int slaveidx = GetIdx(mappingSlave, typeSlave);

            if (masteridx == -1)
            {
                if (typeMaster == MappingType.Sid)
                {
                    masteridx = InsertUnknownSidNode(mappingMaster);
                }
                else if (typeMaster == MappingType.FileName)
                {
                    masteridx = InsertFileNode(mappingMaster);
                }
                else if (typeMaster == MappingType.GPODirectory)
                {
                    masteridx = InsertGPONode(mappingMaster);
                }
                else
                {
                    masteridx = InsertUnknowNode(mappingMaster);
                }
            }
            if (slaveidx == -1)
            {
                if (typeSlave == MappingType.Sid)
                {
                    slaveidx = InsertUnknownSidNode(mappingSlave);
                }
                else if (typeMaster == MappingType.FileName)
                {
                    slaveidx = InsertFileNode(mappingSlave);
                }
                else if (typeMaster == MappingType.GPODirectory)
                {
                    slaveidx = InsertGPONode(mappingSlave);
                }
                else
                {
                    slaveidx = InsertUnknowNode(mappingSlave);
                }

            }
            if (slaveidx != -1 && masteridx != -1 && slaveidx != masteridx)
            {
                int hintId = (int)relationType;
                Relation relation = null;
                if (!relations.ContainsKey(slaveidx))
                {
                    relations.Add(slaveidx, new Dictionary<int, Relation>());
                }
                Dictionary<int, Relation> half = relations[slaveidx];
                if (!half.ContainsKey(masteridx))
                {
                    relation = new Relation();
                    relation.ToId = masteridx;
                    relation.FromId = slaveidx;
                    half.Add(masteridx, relation);
                }
                else
                {
                    relation = relations[slaveidx][masteridx];
                }
                relation.Hint.Add(relationType.ToString());
            }
        }

        public int SearchItem(string name)
        {
            lock (nodes)
            {
                int idx = 0;
                if (name.StartsWith("S-1-5-", StringComparison.InvariantCultureIgnoreCase))
                {
                    idx = GetIdx(name, MappingType.Sid);
                    if (idx >= 0) return idx;
                }
                idx = GetIdx(name, MappingType.Shortname);
                if (idx >= 0) return idx;
                idx = GetIdx(name, MappingType.DistinguishedName);
                if (idx >= 0) return idx;
                idx = GetIdx(name, MappingType.Sid);
                if (idx >= 0) return idx;
                return -1;
            }
        }

        private int GetIdx(string name, MappingType mappingType)
        {
            switch (mappingType)
            {
                case MappingType.Sid:
                    if (nodesBySID.ContainsKey(name.ToLowerInvariant()))
                    {
                        return nodesBySID[name.ToLowerInvariant()].Id;
                    }
                    break;
                case MappingType.DistinguishedName:
                    if (nodesByDN.ContainsKey(name.ToLowerInvariant()))
                    {
                        return nodesByDN[name.ToLowerInvariant()].Id;
                    }
                    break;
                case MappingType.FileName:
                    if (nodesByFilename.ContainsKey(name.ToLowerInvariant()))
                    {
                        return nodesByFilename[name.ToLowerInvariant()].Id;
                    }
                    break;
                case MappingType.GPODirectory:
                    if (nodesGPOByFilename.ContainsKey(name.ToLowerInvariant()))
                    {
                        return nodesGPOByFilename[name.ToLowerInvariant()].Id;
                    }
                    break;
                case MappingType.Shortname:
                    foreach (KeyValuePair<int, Node> nodeEntry in nodes)
                    {
                        if (string.Equals(nodeEntry.Value.Shortname, name, StringComparison.InvariantCultureIgnoreCase))
                            return nodeEntry.Key;
                    }
                    break;
            }
            return -1;
        }

        public Node RetrieveNode(int id)
        {
            try
            {
                return nodes[id];
            }
            catch (KeyNotFoundException)
            {
                Trace.WriteLine("Unable to get node #" + id);
                throw;
            }
        }

        public Dictionary<int, Node> RetrieveNodes(ICollection<int> nodesQueried)
        {
            Dictionary<int, Node> output = new Dictionary<int, Node>();
            foreach (int node in nodesQueried)
            {
                output.Add(node, RetrieveNode(node));
            }
            return output;
        }

        public Dictionary<string, string> GetDatabaseInformation()
        {
            return databaseInformation;
        }

        public ICollection<Relation> SearchRelations(ICollection<int> SourceIds, ICollection<int> knownIds)
        {
            List<Relation> output = new List<Relation>();
            foreach (int sourceId in SourceIds)
            {
                if (relations.ContainsKey(sourceId))
                {
                    var half = relations[sourceId];
                    foreach (int key in half.Keys)
                    {
                        if (!knownIds.Contains(key))
                        {
                            var relation = half[key];
                            output.Add(relation);
                        }
                    }
                }
            }
            return output;
        }

        public List<DataStorageDomainTrusts> GetKnownDomains()
        {
            return KnownDomains;
        }
    }
}
