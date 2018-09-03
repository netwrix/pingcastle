//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.Text;

namespace PingCastle.Database
{
    public interface IDataStorage
    {
        int SearchItem(string name);
        Dictionary<int, Node> RetrieveNodes(List<int> nodes);
        Dictionary<string, string> GetDatabaseInformation();
        List<Relation> SearchRelations(List<int> SourceIds, List<int> knownIds, bool FromMasterToSlave);

        int InsertNode(string shortname, string objectclass, string name, string sid);

        void InsertRelation(string mappingMaster, MappingType typeMaster, string mappingSlave, MappingType typeSlave, RelationType relationType);

    }
}
