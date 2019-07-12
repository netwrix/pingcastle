//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.ADWS;
using PingCastle.RPC;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection;
using System.Text;

namespace PingCastle.Graph.Database
{
    public class LiveDataStorage: IDataStorage
    {
        public Dictionary<int, Node> nodes;
        int index;
        // first index = slave ; second index = master
		public Dictionary<int, Dictionary<int, Relation>> relations;
		public Dictionary<string, string> databaseInformation;

        public List<string> KnownCN = new List<string>();
        public List<string> KnownSID = new List<string>();
        public List<string> KnownFiles = new List<string>();
		public List<int> KnownPGId = new List<int>() { 513, 515 };
        public List<string> CNToInvestigate { get; private set; }
        public List<string> SIDToInvestigate { get; private set; }
		public List<int> PGIdToInvestigate { get; private set; }
        public List<string> FilesToInvestigate { get; private set; }
		public List<DataStorageDomainTrusts> KnownDomains { get; private set; }
		private string serverForSIDResolution;

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
			PGIdToInvestigate = new List<int>();
            FilesToInvestigate = new List<string>();
			KnownDomains = new List<DataStorageDomainTrusts>();
        }

        public void Initialize(ADDomainInfo domainInfo)
        {
            databaseInformation["EngineVersion"] = Assembly.GetExecutingAssembly().GetName().Version.ToString();
            databaseInformation["Date"] = DateTime.Now.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss");
            databaseInformation["DomainName"] = domainInfo.DomainName;
            databaseInformation["DefaultNamingContext"] = domainInfo.DefaultNamingContext;
            databaseInformation["DomainSid"] = domainInfo.DomainSid.Value;
			databaseInformation["DomainNetBIOS"] = domainInfo.NetBIOSName;
			serverForSIDResolution = domainInfo.DnsHostName;
        }

        public List<string> GetCNToInvestigate()
        {
            List<string> output = new List<string>();
			output.AddRange(CNToInvestigate);
            CNToInvestigate.Clear();
            return output;
        }

        public List<string> GetSIDToInvestigate()
        {
            List<string> output = new List<string>();
			output.AddRange(SIDToInvestigate);
            SIDToInvestigate.Clear();
            return output;
        }

		public List<int> GetPrimaryGroupIDToInvestigate()
		{
			List<int> output = new List<int>();
			output.AddRange(PGIdToInvestigate);
			KnownPGId.AddRange(PGIdToInvestigate);
			PGIdToInvestigate.Clear();
			return output;
		}

        public List<string> GetFilesToInvestigate()
        {
            List<string> output = new List<string>();
            output.AddRange(FilesToInvestigate);
            FilesToInvestigate.Clear();
            return output;
        }

        public int InsertNode(string shortname, string objectclass, string name, string sid, ADItem adItem)
        {
			if (String.Equals(objectclass, "unknown", StringComparison.OrdinalIgnoreCase))
			{
				if (name.Contains(",CN=ForeignSecurityPrincipals,DC="))
				{
					objectclass = "foreignsecurityprincipal";
					sid = name.Substring(3, name.IndexOf(',') - 3);
				}
			}
			// reentrance from previous if
			if (String.Equals(objectclass, "foreignsecurityprincipal", StringComparison.OrdinalIgnoreCase))
			{
				// avoid CREATOR OWNER (used for dynamic permissions)
				if (String.Equals(sid, "S-1-3-0", StringComparison.OrdinalIgnoreCase))
					return -1;
				if (String.Equals(sid, "S-1-5-18", StringComparison.OrdinalIgnoreCase))
					return -1;
				string referencedDomain = null;
				string ntaccount = NativeMethods.ConvertSIDToName(sid, serverForSIDResolution, out referencedDomain);
				if (ntaccount == shortname)
				{
					if (String.IsNullOrEmpty(referencedDomain))
						ntaccount = shortname;
					else
						ntaccount = referencedDomain + "\\" + shortname;
				}
				shortname = ntaccount;
				name = sid;
				adItem = null;
			}
			Node node = new Node();
            node.Shortname = shortname;
            node.Type = objectclass;
            node.Dn = name;
			node.Sid = sid;
			node.ADItem = adItem;
            
			//12345
			lock (nodes)
			{
                Trace.WriteLine("Inserting node " + index + " name=" + node.Name + " sid=" + node.Sid + " shortname=" + node.Shortname);
                node.Id = index;
				nodes.Add(index, node);
                if (!string.IsNullOrEmpty(name))
                {
                    if (name.StartsWith("\\\\"))
                    {
                        KnownFiles.Add(name);
                        if (FilesToInvestigate.Contains(name))
                            FilesToInvestigate.Remove(name);
                    }
                    else
                    {
                        KnownCN.Add(name);
                        if (CNToInvestigate.Contains(name))
                            CNToInvestigate.Remove(name);
                    }
                } 
                if (!String.IsNullOrEmpty(sid))
				{
					KnownSID.Add(sid);
					if (SIDToInvestigate.Contains(sid))
						SIDToInvestigate.Remove(sid);
					// handle primary group id
					if (objectclass == "group")
					{
						if (sid.StartsWith("S-1-5-21-"))
						{
							var part = sid.Split('-');
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
			if (String.IsNullOrEmpty(mapping))
			{
				Trace.WriteLine("Ignoring addition of mapping " + mapping + "type = " + type);
				return;
			}
            else if (mapping.StartsWith("\\\\"))
            {
                if (!KnownFiles.Contains(mapping))
                    if (!FilesToInvestigate.Contains(mapping))
                        FilesToInvestigate.Add(mapping);
            }
            else
            {
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
					masteridx = InsertNode(mappingMaster, "foreignsecurityprincipal", mappingMaster, mappingMaster, null);
                }
                else
                {
					masteridx = InsertNode(mappingMaster, "unknown", mappingMaster, null, null);
                }
            }
            if (slaveidx == -1)
            {
				if (typeSlave == MappingType.Sid)
                {
					slaveidx = InsertNode(mappingSlave, "foreignsecurityprincipal", mappingSlave, mappingSlave, null);
                }
                else
                {
					slaveidx = InsertNode(mappingSlave, "unknown", mappingSlave, null, null);
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

        public Dictionary<int, Node> RetrieveNodes(List<int> nodesQueried)
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

        public List<Relation> SearchRelations(List<int> SourceIds, List<int> knownIds)
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
