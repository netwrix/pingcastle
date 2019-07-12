//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.Text;
using PingCastle.ADWS;
using PingCastle.RPC;
using System.Security.Principal;

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


    public interface IDataStorage
    {
        // used to store various information about the domain in general (its FQDN, its SID, ...)
        Dictionary<string, string> GetDatabaseInformation();
        
        // used to locate an item based on its name
        int SearchItem(string name);
        // once, the ID located by the previous function, return the node
        Node RetrieveNode(int id);
        // generated lookup function
		Dictionary<int, Node> RetrieveNodes(List<int> nodes);
        // based on a node list, return all path to other nodes (at the exclusion of the knownId ones)
		List<Relation> SearchRelations(List<int> SourceIds, List<int> knownIds);

        // create a node
        int InsertNode(string shortname, string objectclass, string name, string sid, ADItem adItem);
        // create a link between 2 nodes
        void InsertRelation(string mappingMaster, MappingType typeMaster, string mappingSlave, MappingType typeSlave, RelationType relationType);

		List<DataStorageDomainTrusts> GetKnownDomains();

        // used to retrieve objects in queue and not examined
        List<string> GetCNToInvestigate();
        List<string> GetSIDToInvestigate();
        List<int> GetPrimaryGroupIDToInvestigate();
        List<string> GetFilesToInvestigate();
	}
}
