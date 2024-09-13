//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.ADWS;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.Serialization;
using System.Xml.Serialization;

namespace PingCastle.Data
{

    public enum CompromiseGraphDataObjectRisk
    {
        Critical,
        High,
        Medium,
        Other
    }

    [DebuggerDisplay("{Name}")]
    public class CompromiseGraphData
    {
        public void SetExportLevel(PingCastleReportDataExportLevel level)
        {
            //Level = level;
        }

        public List<SingleCompromiseGraphData> Data { get; set; }

        public List<CompromiseGraphDependancyData> Dependancies { get; set; }
        public List<CompromiseGraphAnomalyAnalysisData> AnomalyAnalysis { get; set; }

        public int GlobalScore { get; set; }
        public int StaleObjectsScore { get; set; }
        public int PrivilegiedGroupScore { get; set; }
        public int TrustScore { get; set; }
        public int AnomalyScore { get; set; }

        [XmlIgnore]
        public IList<DomainKey> DomainKnown
        {
            get
            {
                var output = new List<DomainKey>();
                foreach (var d in Dependancies)
                {
                    output.Add(d.Domain);
                }
                return output;
            }
        }
    }

    public class CompromiseGraphAnomalyAnalysisData
    {
        [XmlAttribute]
        public CompromiseGraphDataObjectRisk ObjectRisk { get; set; }
        [XmlAttribute]
        public int NumberOfObjectsScreened { get; set; }
        [XmlAttribute]
        public int NumberOfObjectsWithIndirect { get; set; }
        [XmlAttribute]
        public int MaximumIndirectNumber { get; set; }
        [XmlAttribute]
        public int MaximumDirectIndirectRatio { get; set; }
        [XmlAttribute]
        [DefaultValue(false)]
        public bool CriticalObjectFound { get; set; }
    }

    public enum CompromiseGraphDataTypology
    {
        [Description("Admin groups")]
        PrivilegedAccount = 10,
        [Description("Critical Infrastructure")]
        Infrastructure = 20,
        [Description("User Defined")]
        UserDefined = 100,
    }

    [DebuggerDisplay("{Name}")]
    [XmlType("userMember")]
    public class SingleCompromiseGraphUserMemberData
    {
        [XmlAttribute]
        public string Name { get; set; }
        [XmlAttribute]
        public string DistinguishedName { get; set; }
        [XmlAttribute]
        [DefaultValue(false)]
        public bool IsEnabled { get; set; }
        [XmlAttribute]
        [DefaultValue(false)]
        public bool IsActive { get; set; }
        [XmlAttribute]
        [DefaultValue(false)]
        public bool IsLocked { get; set; }
        [XmlAttribute]
        [DefaultValue(false)]
        public bool DoesPwdNeverExpires { get; set; }
        [XmlAttribute]
        [DefaultValue(false)]
        public bool CanBeDelegated { get; set; }
        [XmlAttribute]
        public DateTime LastLogonTimestamp { get; set; }
        [XmlAttribute]
        public DateTime PwdLastSet { get; set; }
        [XmlAttribute]
        [DefaultValue(false)]
        public bool SmartCardRequired { get; set; }
        [XmlAttribute]
        [DefaultValue(false)]
        public bool IsService { get; set; }
        // not used for the moment
        [XmlIgnore]
        public List<string> SPN { get; set; }
        [XmlAttribute]
        [DefaultValue(false)]
        public bool IsPwdNotRequired { get; set; }
    }

    [DebuggerDisplay("{Name}")]
    [XmlType("computerMember")]
    public class SingleCompromiseGraphComputerMemberData
    {
        [XmlAttribute]
        public string Name { get; set; }
        [XmlAttribute]
        public string DistinguishedName { get; set; }
        [XmlAttribute]
        [DefaultValue(false)]
        public bool IsEnabled { get; set; }
        [XmlAttribute]
        [DefaultValue(false)]
        public bool IsActive { get; set; }
        [DefaultValue(false)]
        [XmlAttribute]
        public bool IsLocked { get; set; }
        [DefaultValue(false)]
        [XmlAttribute]
        public bool CanBeDelegated { get; set; }
        [XmlAttribute]
        public DateTime LastLogonTimestamp { get; set; }
        // not used for the moment
        [XmlIgnore]
        public List<string> SPN { get; set; }
    }

    [XmlType("indirectMember")]
    public class SingleCompromiseGraphIndirectMemberData
    {
        [XmlAttribute]
        public string Name { get; set; }
        [XmlAttribute]
        public string Sid { get; set; }
        [XmlAttribute]
        public int Distance { get; set; }
        [XmlAttribute]
        public string AuthorizedObject { get; set; }
        [XmlAttribute]
        public string Path { get; set; }
    }

    [XmlType("dependancyMember")]
    public class SingleCompromiseGraphDependancyMemberData
    {
        [XmlAttribute]
        public string Name { get; set; }
        [XmlAttribute]
        public string Sid { get; set; }
    }

    [XmlType("detail")]
    public class CompromiseGraphDependancyDetailData
    {
        [XmlAttribute]
        public CompromiseGraphDataTypology Typology { get; set; }
        [XmlAttribute]
        public int NumberOfResolvedItems { get; set; }
        [XmlAttribute]
        public int NumberOfUnresolvedItems { get; set; }
        [XmlAttribute]
        public int NumberOfGroupImpacted { get; set; }
        [XmlIgnore]
        public List<string> Items { get; set; }
    }

    [XmlType("dependancyData")]
    public class CompromiseGraphDependancyData
    {
        [XmlAttribute]
        public string Netbios { get; set; }
        [XmlAttribute]
        public string FQDN { get; set; }
        [XmlAttribute]
        public string Sid { get; set; }

        public List<CompromiseGraphDependancyDetailData> Details { get; set; }

        private DomainKey _domain;
        [XmlIgnore]
        public DomainKey Domain
        {
            get
            {
                if (_domain == null)
                {
                    _domain = DomainKey.Create(FQDN, Sid, Netbios);
                }
                return _domain;
            }
        }
    }

    [XmlType("singleDependancyData")]
    public class SingleCompromiseGraphDependancyData
    {
        [XmlAttribute]
        public string Netbios { get; set; }
        [XmlAttribute]
        public string FQDN { get; set; }
        [XmlAttribute]
        public string Sid { get; set; }
        [XmlAttribute]
        public int NumberOfResolvedItems { get; set; }
        [XmlAttribute]
        public int NumberOfUnresolvedItems { get; set; }
        public List<SingleCompromiseGraphDependancyMemberData> Items { get; set; }

    }

    [XmlType("deletedData")]
    public class SingleCompromiseGraphDeletedData
    {
        [XmlAttribute]
        public string Sid { get; set; }
    }

    [XmlType("data")]
    public class SingleCompromiseGraphData
    {
        [IgnoreDataMember]
        [XmlIgnore]
        public PingCastleReportDataExportLevel Level { get; set; }

        [XmlAttribute]
        public string Name { get; set; }
        [XmlAttribute]
        public string Description { get; set; }
        [XmlAttribute]
        public CompromiseGraphDataTypology Typology { get; set; }
        [XmlAttribute]
        public CompromiseGraphDataObjectRisk ObjectRisk { get; set; }

        public bool ShouldSerializeNodes() { return (int)Level <= (int)PingCastleReportDataExportLevel.Full; }
        public List<SingleCompromiseGraphNodeData> Nodes { get; set; }

        public bool ShouldSerializeLinks() { return (int)Level <= (int)PingCastleReportDataExportLevel.Full; }
        public List<SingleCompromiseGraphLinkData> Links { get; set; }

        [DefaultValue(false)]
        public bool OnDemandAnalysis { get; set; }

        [XmlAttribute]
        [DefaultValue(false)]
        public bool CriticalObjectFound { get; set; }

        public int NumberOfDirectUserMembers { get; set; }

        public int NumberOfDirectComputerMembers { get; set; }

        public int NumberOfIndirectMembers { get; set; }

        public int NumberOfDeletedObjects { get; set; }

        public bool ShouldSerializeDirectUserMembers() { return (int)Level <= (int)PingCastleReportDataExportLevel.Full; }
        public List<SingleCompromiseGraphUserMemberData> DirectUserMembers { get; set; }

        public bool ShouldSerializeDirectComputerMembers() { return (int)Level <= (int)PingCastleReportDataExportLevel.Full; }
        public List<SingleCompromiseGraphComputerMemberData> DirectComputerMembers { get; set; }

        public bool ShouldSerializeIndirectMembers() { return (int)Level <= (int)PingCastleReportDataExportLevel.Full; }
        public List<SingleCompromiseGraphIndirectMemberData> IndirectMembers { get; set; }

        public bool ShouldSerializeDependancies() { return (int)Level <= (int)PingCastleReportDataExportLevel.Light; }
        public List<SingleCompromiseGraphDependancyData> Dependancies { get; set; }

        public bool ShouldSerializeDeletedObjects() { return (int)Level <= (int)PingCastleReportDataExportLevel.Full; }
        public List<SingleCompromiseGraphDeletedData> DeletedObjects { get; set; }
    }

    [XmlType("node")]
    public class SingleCompromiseGraphNodeData
    {
        [XmlAttribute]
        public int Id { get; set; }
        [XmlAttribute]
        public string Name { get; set; }
        [XmlAttribute]
        public string Type { get; set; }

        [IgnoreDataMember]
        [XmlIgnore]
        public bool IsTypeAUser
        {
            get
            {
                return (string.Equals(Type, "user", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(Type, "inetOrgPerson", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(Type, "msDS-GroupManagedServiceAccount", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(Type, "msDS-ManagedServiceAccount", StringComparison.OrdinalIgnoreCase)
                    );
            }
        }

        [XmlAttribute]
        public string ShortName { get; set; }
        [XmlAttribute]
        public int Distance { get; set; }
        [XmlAttribute]
        [DefaultValue(false)]
        public bool Suspicious { get; set; }
        [XmlAttribute]
        [DefaultValue(false)]
        public bool Critical { get; set; }
        // used when building the structure
        [XmlIgnore]
        [IgnoreDataMember]
        internal ADItem ADItem { get; set; }
    }

    [XmlType("link")]
    public class SingleCompromiseGraphLinkData
    {
        [XmlAttribute]
        public int Source { get; set; }
        [XmlAttribute]
        public int Target { get; set; }
        [XmlAttribute]
        public string Hints { get; set; }
    }
}
