//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Healthcheck;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Xml.Serialization;

namespace PingCastle.Data
{
	[DebuggerDisplay("{Name}")]
	public class CompromiseGraphData
	{
		public string EngineVersion { get; set; }
		public DateTime GenerationDate { get; set; }

		public string DomainFQDN { get; set; }
		public string DomainSid { get; set; }

		private DomainKey _domain;
		[XmlIgnore]
		public DomainKey Domain
		{
			get
			{
				if (_domain == null)
				{
					_domain = new DomainKey(DomainFQDN, DomainSid);
				}
				return _domain;
			}
		}

		public List<SingleCompromiseGraphData> Data { get; set; }
	}

	public class SingleCompromiseGraphData
	{
		public string Name { get; set; }
		public string Description { get; set; }
		public List<SingleCompromiseGraphNodeData> Nodes { get; set; }
		public List<SingleCompromiseGraphLinkData> Links { get; set; }
		public bool OnDemandAnalysis { get; set; }
		public bool UnusualGroup { get; set; }
	}

	public class SingleCompromiseGraphNodeData
	{
		public int Id { get; set; }
		public string Name { get; set; }
		public string Type { get; set; }
		public string ShortName { get; set; }
		public int Distance {get; set; }
	}

	public class SingleCompromiseGraphLinkData
	{
		public int Source { get; set; }
		public int Target { get; set; }
		public List<string> Hints { get; set; }
	}
}
