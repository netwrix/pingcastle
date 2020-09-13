using PingCastle.ADWS;
using PingCastle.Data;
using System;
using System.Collections.Generic;

namespace PingCastle.Graph.Reporting
{
	public class GraphSingleObject
	{
		public GraphSingleObject(string name, string description, CompromiseGraphDataObjectRisk risk = CompromiseGraphDataObjectRisk.Other)
		{
			Name = name;
			Description = description;
			Risk = risk;
		}
		public string Name { get; set; }
		public string Description { get; set; }
		public CompromiseGraphDataObjectRisk Risk { get; set; }
	}

	public class GraphObjectReference
	{
		public Dictionary<CompromiseGraphDataTypology, List<GraphSingleObject>> Objects {get;set;}
        public List<string> TechnicalObjects { get; set; }

		public GraphObjectReference(ADDomainInfo data)
		{
			Objects = new Dictionary<CompromiseGraphDataTypology, List<GraphSingleObject>>()
			{
				{CompromiseGraphDataTypology.PrivilegedAccount, new List<GraphSingleObject>(){
					new GraphSingleObject("S-1-5-32-544","Administrators", CompromiseGraphDataObjectRisk.Critical),
					new GraphSingleObject("S-1-5-32-548","Account Operators", CompromiseGraphDataObjectRisk.High),
					new GraphSingleObject("S-1-5-32-549","Server Operators", CompromiseGraphDataObjectRisk.High),
					new GraphSingleObject("S-1-5-32-550","Print Operators", CompromiseGraphDataObjectRisk.Medium),
					new GraphSingleObject("S-1-5-32-551","Backup Operators", CompromiseGraphDataObjectRisk.High),
					new GraphSingleObject("S-1-5-32-569","Certificate Operators", CompromiseGraphDataObjectRisk.Medium),
					new GraphSingleObject("S-1-5-32-552", "Replicator", CompromiseGraphDataObjectRisk.Medium),
					new GraphSingleObject(data.DomainSid.Value + "-500","Administrator", CompromiseGraphDataObjectRisk.Critical),
					new GraphSingleObject(data.DomainSid.Value + "-512","Domain Administrators", CompromiseGraphDataObjectRisk.Critical),
					new GraphSingleObject(data.DomainSid.Value + "-517","Certificate Publishers"),
					new GraphSingleObject(data.DomainSid.Value + "-518","Schema Administrators", CompromiseGraphDataObjectRisk.Critical),
					new GraphSingleObject(data.DomainSid.Value + "-519","Enterprise Administrators", CompromiseGraphDataObjectRisk.Critical),
					new GraphSingleObject(data.DomainSid.Value + "-526","Key Administrators", CompromiseGraphDataObjectRisk.Medium),
					new GraphSingleObject(data.DomainSid.Value + "-527","Enterprise Key Administrators", CompromiseGraphDataObjectRisk.Medium)
                }},
				{CompromiseGraphDataTypology.Infrastructure, new List<GraphSingleObject>(){
					new GraphSingleObject(data.DomainSid.Value,"Domain Root", CompromiseGraphDataObjectRisk.Medium),
                    new GraphSingleObject(data.DomainSid.Value + "-498","Enterprise Read Only Domain Controllers"),
					new GraphSingleObject(data.DomainSid.Value + "-502","Krbtgt account", CompromiseGraphDataObjectRisk.Medium),
					new GraphSingleObject(data.DomainSid.Value + "-516","Domain Controllers", CompromiseGraphDataObjectRisk.Critical),
					new GraphSingleObject(data.DomainSid.Value + "-520","Group Policy Creator Owners", CompromiseGraphDataObjectRisk.Medium),
					new GraphSingleObject(data.DomainSid.Value + "-521","Read Only Domain Controllers", CompromiseGraphDataObjectRisk.Medium),
					new GraphSingleObject("CN=Builtin," + data.DefaultNamingContext,"Builtin OU", CompromiseGraphDataObjectRisk.Medium),
					new GraphSingleObject("CN=Users," + data.DefaultNamingContext,"Users container", CompromiseGraphDataObjectRisk.Medium),
					new GraphSingleObject("CN=Computers," + data.DefaultNamingContext,"Computers container", CompromiseGraphDataObjectRisk.Medium),
					new GraphSingleObject("CN=NTAuthCertificates,CN=Public Key Services,CN=Services," + data.ConfigurationNamingContext,"Certificate store", CompromiseGraphDataObjectRisk.Medium)
                }},
				{CompromiseGraphDataTypology.UserDefined, new List<GraphSingleObject>(){
				}}
            };

			foreach (var typology in Objects.Keys)
			{
				Objects[typology].Sort((GraphSingleObject a, GraphSingleObject b)
					=>
					{
						return String.Compare(a.Description, b.Description);
					});
			}
            TechnicalObjects = new List<string>();
            TechnicalObjects.Add(data.DomainSid.Value + "-525");
		}
	}

}
