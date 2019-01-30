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
        int SearchItem(string name);
		Node RetrieveNode(int id);
		Dictionary<int, Node> RetrieveNodes(List<int> nodes);
		Dictionary<string, string> GetDatabaseInformation();
        List<Relation> SearchRelations(List<int> SourceIds, List<int> knownIds);

        int InsertNode(string shortname, string objectclass, string name, string sid, ADItem adItem);

        void InsertRelation(string mappingMaster, MappingType typeMaster, string mappingSlave, MappingType typeSlave, RelationType relationType);

		List<DataStorageDomainTrusts> GetKnownDomains();

		bool IsSIDAlreadyInserted(string sid);
	}
}
