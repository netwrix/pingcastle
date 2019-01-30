//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Healthcheck;
using PingCastle.Rules;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Text;
using System.Xml.Serialization;
using PingCastle.ADWS;
using PingCastle.Graph.Database;
using System.Runtime.Serialization;

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
	public class CompromiseGraphData : IRiskEvaluationOnObjective, IPingCastleReport
	{
		public string EngineVersion { get; set; }
		public DateTime GenerationDate { get; set; }

		public string GetHumanReadableFileName()
		{
			return "ad_cg_" + DomainFQDN + ".html";
		}
		public string GetMachineReadableFileName()
		{
			return "ad_cg_" + DomainFQDN + ".xml";
		}

		public void SetExportLevel(PingCastleReportDataExportLevel level)
		{
			//Level = level;
		}

		public string DomainFQDN { get; set; }
		public string DomainSid { get; set; }
		public string DomainNetBIOS { get; set; }

		private DomainKey _domain;
		[XmlIgnore]
		public DomainKey Domain
		{
			get
			{
				if (_domain == null)
				{
					_domain = new DomainKey(DomainFQDN, DomainSid, DomainNetBIOS);
				}
				return _domain;
			}
		}

		public List<SingleCompromiseGraphData> Data { get; set; }
		public List<CompromiseGraphRiskRule> RiskRules { get; set; }
		public List<CompromiseGraphDependancyData> Dependancies { get; set; }
		public List<CompromiseGraphAnomalyAnalysisData> AnomalyAnalysis { get; set; }

		public int GlobalScore { get; set; }
		public int StaleObjectsScore { get; set; }
		public int PrivilegiedGroupScore { get; set; }
		public int TrustScore { get; set; }
		public int AnomalyScore { get; set; }

		[XmlIgnore]
		public IList<IRuleScore> AllRiskRules { get { return RiskRules.ConvertAll(x => { return (IRuleScore)x; }); } }
		[XmlIgnore]
		public IList<DomainKey> DomainKnown
		{
			get
			{
				var output = new List<DomainKey>();
				output.Add(Domain);
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
		public CompromiseGraphDataObjectRisk ObjectRisk { get; set; }
		public int NumberOfObjectsScreened { get; set; }
		public int NumberOfObjectsWithIndirect {get;set;}
		public int MaximumIndirectNumber { get; set; }
		public int MaximumDirectIndirectRatio { get; set; }
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

	public class CompromiseGraphRiskRule : IRuleScore
	{
		public CompromiseGraphRiskRule()
        {
            Level = PingCastleReportDataExportLevel.Full;
        }

		[IgnoreDataMember]
		[XmlIgnore]
        public PingCastleReportDataExportLevel Level { get; set; }

        public int Points { get; set; }
		public bool Achieved { get; set; }

        public RiskRuleCategory Category { get; set; }

		public RiskModelObjective Objective { get; set; }

        public string RiskId { get; set; }

        public string Rationale { get; set; }

		public bool ShouldSerializeDetails() { return (int)Level <= (int)PingCastleReportDataExportLevel.Full; }
        public List<string> Details { get; set; }
		
		public List<CompromiseGraphRiskRuleDetail> ImpactedAssets { get; set; }

	}

	public class CompromiseGraphRiskRuleDetail
	{
		public string AssetName { get; set; }
		public string Rationale { get; set; }
		public List<string> Details { get; set; }
	}

	[DebuggerDisplay("{Name}")]
	public class SingleCompromiseGraphUserMemberData
	{
		public string Name { get; set; }

		public string DistinguishedName { get; set; }

		public bool IsEnabled { get; set; }

		public bool IsActive { get; set; }

		public bool IsLocked { get; set; }

		public bool DoesPwdNeverExpires { get; set; }

		public bool CanBeDelegated { get; set; }

		public DateTime LastLogonTimestamp { get; set; }

		public DateTime PwdLastSet { get; set; }

		public bool SmartCardRequired { get; set; }

		public bool IsService { get; set; }

		public List<string> SPN { get; set; }

		public bool IsPwdNotRequired { get; set; }
	}

	[DebuggerDisplay("{Name}")]
	public class SingleCompromiseGraphComputerMemberData
	{
		public string Name { get; set; }

		public string DistinguishedName { get; set; }

		public bool IsEnabled { get; set; }

		public bool IsActive { get; set; }

		public bool IsLocked { get; set; }

		public bool CanBeDelegated { get; set; }

		public DateTime LastLogonTimestamp { get; set; }

		public List<string> SPN { get; set; }
	}

	public class SingleCompromiseGraphIndirectMemberData
	{
		public string Name { get; set; }
		public string Sid { get; set; }
		public int Distance { get; set; }
		public string AuthorizedObject { get; set; }
		public string Path { get; set; }
	}

	public class SingleCompromiseGraphDependancyMemberData
	{
		public string Name { get; set; }
		public string Sid { get; set; }
	}

	public class CompromiseGraphDependancyDetailData
	{
		public CompromiseGraphDataTypology Typology { get; set; }
		public int NumberOfResolvedItems { get; set; }
		public int NumberOfUnresolvedItems { get; set; }
		public int NumberOfGroupImpacted { get; set; }
		[XmlIgnore]
		public List<string> Items { get; set; }
	}

	public class CompromiseGraphDependancyData
	{
		public string Netbios { get; set; }
		public string FQDN { get; set; }
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
					_domain = new DomainKey(FQDN, Sid, Netbios);
				}
				return _domain;
			}
		}
	}

	public class SingleCompromiseGraphDependancyData
	{
		public string Netbios { get; set; }
		public string FQDN { get; set; }
		public string Sid {get; set;}
		public int NumberOfResolvedItems { get; set; }
		public int NumberOfUnresolvedItems { get; set; }
		public List<SingleCompromiseGraphDependancyMemberData> Items { get; set; }

	}
	
	public class SingleCompromiseGraphDeletedData
	{
		public string Sid { get; set; }
	}

	public class SingleCompromiseGraphData
	{
		public string Name { get; set; }
		public string Description { get; set; }
		public CompromiseGraphDataTypology Typology { get; set; }
		public CompromiseGraphDataObjectRisk ObjectRisk { get; set; }
		public List<SingleCompromiseGraphNodeData> Nodes { get; set; }
		public List<SingleCompromiseGraphLinkData> Links { get; set; }
		public bool OnDemandAnalysis { get; set; }
		public bool CriticalObjectFound { get; set; }
		public List<SingleCompromiseGraphUserMemberData> DirectUserMembers { get; set; }
		public List<SingleCompromiseGraphComputerMemberData> DirectComputerMembers { get; set; }
		public List<SingleCompromiseGraphIndirectMemberData> IndirectMembers { get; set; }
		public List<SingleCompromiseGraphDependancyData> Dependancies { get; set; }
		public List<SingleCompromiseGraphDeletedData> DeletedObjects { get; set; }
	}

	public class SingleCompromiseGraphNodeData
	{
		public int Id { get; set; }
		public string Name { get; set; }
		public string Type { get; set; }
		public string ShortName { get; set; }
		public int Distance {get; set; }
		public bool Suspicious { get; set; }
		public bool Critical { get; set; }
		// used when building the structure
		[XmlIgnore]
		public ADItem ADItem { get; set; }
	}

	public class SingleCompromiseGraphLinkData
	{
		public int Source { get; set; }
		public int Target { get; set; }
		public List<string> Hints { get; set; }
	}
}
