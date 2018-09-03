//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.ADWS;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection;
using System.Text;

namespace PingCastle.Database
{
    public class LiveDataStorage: IDataStorage
    {
        Dictionary<int, Node> nodes;
        int index;
        // first index = slave ; second index = master
        Dictionary<int, Dictionary<int, Relation>> relations;
        Dictionary<string, string> databaseInformation;

        public List<string> KnownCN = new List<string>();
        public List<string> KnownSID = new List<string>();
        public List<string> CNToInvestigate { get; private set; }
        public List<string> SIDToInvestigate { get; private set; }

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
			index = 0;
            relations = new Dictionary<int, Dictionary<int, Relation>>();
            relationsOnHold = new List<RelationOnHold>();
            databaseInformation = new Dictionary<string, string>();
            SIDToInvestigate = new List<string>();
            CNToInvestigate = new List<string>();
        }

        public void Initialize(ADDomainInfo domainInfo)
        {
            databaseInformation["EngineVersion"] = Assembly.GetExecutingAssembly().GetName().Version.ToString();
            databaseInformation["Date"] = DateTime.Now.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss");
            databaseInformation["DomainName"] = domainInfo.DomainName;
            databaseInformation["DefaultNamingContext"] = domainInfo.DefaultNamingContext;
            databaseInformation["DomainSid"] = domainInfo.DomainSid.Value;
        }

        public List<string> GetCNToInvestigate()
        {
            List<string> output = new List<string>();
            foreach (string s in CNToInvestigate)
            {
                output.Add(s);
            }
            CNToInvestigate.Clear();
            return output;
        }

        public List<string> GetSIDToInvestigate()
        {
            List<string> output = new List<string>();
            foreach (string s in SIDToInvestigate)
            {
                output.Add(s);
            }
            SIDToInvestigate.Clear();
            return output;
        }

        public int InsertNode(string shortname, string objectclass, string name, string sid)
        {
            Node node = new Node();
            node.Id = index;
            node.Shortname = shortname;
            node.Type = objectclass;
            node.Dn = name;
            if (!String.IsNullOrEmpty(name))
            {
                KnownCN.Add(name);
                if (CNToInvestigate.Contains(name))
                    CNToInvestigate.Remove(name);
            }
            node.Sid = sid;
            nodes.Add(index, node);
            if (!String.IsNullOrEmpty(sid))
            {
                KnownSID.Add(sid);
                if (SIDToInvestigate.Contains(sid))
                    SIDToInvestigate.Remove(sid);
            }
            return index++;
        }

        public void InsertRelation(string mappingMaster, MappingType typeMaster, string mappingSlave, MappingType typeSlave, RelationType relationType)
        {
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
			if (String.IsNullOrEmpty(mapping) || mapping.StartsWith("\\\\"))
			{
				Trace.WriteLine("Ignoring addition of mapping " + mapping + "type = " + type);
				return;
			}
            switch (type)
            {
                case MappingType.Name:
                    if (!KnownCN.Contains(mapping))
                        if (!CNToInvestigate.Contains(mapping))
                            CNToInvestigate.Add(mapping);
                    break;
                case MappingType.Sid:
                    if (mapping.StartsWith("S-1-5-32-") || mapping.StartsWith(databaseInformation["DomainSid"]))
                        if (!KnownSID.Contains(mapping))
                            if (!SIDToInvestigate.Contains(mapping))
                                SIDToInvestigate.Add(mapping);
                    break;
            }
        }

        public void InsertRelationOnHold(string serverForSIDResolution)
        {
            foreach (RelationOnHold relation in relationsOnHold)
            {
				try
				{
					InsertRelation(serverForSIDResolution, relation.mappingMaster, relation.typeMaster, relation.mappingSlave, relation.typeSlave, relation.relationType);
				}
				catch (Exception)
				{
					Trace.WriteLine("An exception occured when working on : {" + relation.mappingMaster + "," + relation.typeMaster + "," + relation.mappingSlave + "," + relation.typeSlave + "," + relation.relationType + "}");
					throw;
				}
            }
            relationsOnHold.Clear();
        }

        private void InsertRelation(string serverForSIDResolution, string mappingMaster, MappingType typeMaster, string mappingSlave, MappingType typeSlave, RelationType relationType)
        {
            int masteridx = GetIdx(mappingMaster, typeMaster);
            int slaveidx = GetIdx(mappingSlave, typeSlave);

            if (masteridx == -1)
            {
                if (typeMaster == MappingType.Sid)
                {
                    string ntaccount = NativeMethods.ConvertSIDToName(mappingMaster, serverForSIDResolution);
                    masteridx = InsertNode(mappingMaster, "unknown", ntaccount, mappingMaster);
                }
                else
                {
                    masteridx = InsertNode(mappingMaster, "unknown", mappingMaster, null);
                }
            }
            if (slaveidx == -1)
            {
                if (typeMaster == MappingType.Sid)
                {
                    slaveidx = InsertNode(mappingSlave, "unknown", mappingSlave, mappingSlave);
                }
                else
                {
                    slaveidx = InsertNode(mappingSlave, "unknown", mappingSlave, null);
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
            int idx = 0;
            if (name.StartsWith("S-1-5-", StringComparison.InvariantCultureIgnoreCase))
            {
                idx = GetIdx(name, MappingType.Sid);
                if (idx >= 0) return idx;
            }
            idx = GetIdx(name, MappingType.Shortname);
            if (idx >= 0) return idx;
            idx = GetIdx(name, MappingType.Name);
            if (idx >= 0) return idx;
            idx = GetIdx(name, MappingType.Sid);
            if (idx >= 0) return idx;
            return -1;
        }

        private int GetIdx(string name, MappingType mappingType)
        {
            switch (mappingType)
            {
                case MappingType.Sid:
					foreach (KeyValuePair<int, Node> nodeEntry in nodes)
                    {
						if (String.Equals(nodeEntry.Value.Sid, name, StringComparison.InvariantCultureIgnoreCase))
							return nodeEntry.Key;
                    }
                    break;
                case MappingType.Name:
					foreach (KeyValuePair<int, Node> nodeEntry in nodes)
                    {
						if (String.Equals(nodeEntry.Value.Name, name, StringComparison.InvariantCultureIgnoreCase))
							return nodeEntry.Key;
                    }
                    break;
                case MappingType.Shortname:
					foreach (KeyValuePair<int, Node> nodeEntry in nodes)
                    {
						if (String.Equals(nodeEntry.Value.Shortname, name, StringComparison.InvariantCultureIgnoreCase))
							return nodeEntry.Key;
                    }
                    break;
            }
            return -1;
        }

        public Dictionary<int, Node> RetrieveNodes(List<int> nodesQueried)
        {
            Dictionary<int, Node> output = new Dictionary<int, Node>();
            foreach (int node in nodesQueried)
            {
                output.Add(node, nodes[node]);
            }
            return output;
        }

        public Dictionary<string, string> GetDatabaseInformation()
        {
            return databaseInformation;
        }

        public List<Relation> SearchRelations(List<int> SourceIds, List<int> knownIds, bool FromMasterToSlave)
        {
            if (FromMasterToSlave)
            {
                throw new ApplicationException("reverse direction is not allowed in live mode (all Security Descriptors need to be analyzed)");
            }
            List<Relation> output = new List<Relation>();
            foreach (int sourceId in SourceIds)
            {
                if (relations.ContainsKey(sourceId))
                {
                    var half = relations[sourceId];
                    foreach (int key in half.Keys)
                    {
                        if (!knownIds.Contains(key))
                            output.Add(half[key]);
                    }
                }
            }
            return output;
        }



    }
}
