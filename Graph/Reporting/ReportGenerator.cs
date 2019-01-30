//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Data;
using PingCastle.Graph.Database;
using PingCastle.Graph;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection;
using System.Security.Principal;
using PingCastle.ADWS;
using PingCastle.Graph.Rules;
using PingCastle.Rules;
using System.Net;
using PingCastle.Export;
using PingCastle.Graph.Reporting;

namespace PingCastle.Reporting
{
	public class ReportGenerator : IPingCastleAnalyzer<CompromiseGraphData>
	{
		public static int MaxDepth { get; set; }
		public static int MaxNodes { get; set; }

		static ReportGenerator()
		{
			MaxDepth = 30;
			MaxNodes = 1000;
		}

		private IDataStorage storage;
		private List<string> stopNodes = new List<string>();

		public CompromiseGraphData PerformAnalyze(PingCastleAnalyzerParameters parameters)
		{
			ExportDataFromActiveDirectoryLive export = new ExportDataFromActiveDirectoryLive(parameters.Server, parameters.Port, parameters.Credential);
			var ObjectReference = export.ExportData(parameters.AdditionalNamesForDelegationAnalysis);
			storage = export.Storage;
			CompromiseGraphData data = new CompromiseGraphData();
			data.GenerationDate = DateTime.Now;
			Version version = Assembly.GetExecutingAssembly().GetName().Version;
			data.EngineVersion = version.ToString(4);
#if DEBUG
			data.EngineVersion += " Beta";
#endif

			Dictionary<string, string> databaseProperties = storage.GetDatabaseInformation();
			data.DomainSid = databaseProperties["DomainSid"];
			data.DomainFQDN = databaseProperties["DomainName"];
			data.DomainNetBIOS = databaseProperties["DomainNetBIOS"];
			data.Data = new List<SingleCompromiseGraphData>();
			string domainContext = "DC=" + string.Join(",DC=", data.DomainFQDN.Split('.'));

			PrepareStopNodes(ObjectReference);

			PrepareDetailledData(data, ObjectReference);
			PrepareDependancyGlobalData(data);
			PrepareAnomalyAnalysisData(data);
			PrepareRiskData(data);
			//PrepareObjectiveData(data);
			return data;
		}

		void PrepareDetailledData(CompromiseGraphData data, GraphObjectReference ObjectReference)
		{
			foreach (var typology in ObjectReference.Objects.Keys)
			{
				foreach (var obj in ObjectReference.Objects[typology])
				{
					ProduceReportFile(data, typology, obj.Risk, obj.Description, obj.Name);
				}
			}
			data.Data.Sort(
				(SingleCompromiseGraphData a, SingleCompromiseGraphData b)
				=>
				{
					return string.Compare(a.Description, b.Description);
				});
		}

		private void PrepareDependancyGlobalData(CompromiseGraphData data)
		{
			var reference = new Dictionary<string, CompromiseGraphDependancyData>();
			foreach (var sg in data.Data)
			{
				foreach (SingleCompromiseGraphDependancyData d in sg.Dependancies)
				{
					// beware: we are using exising SingleCompromiseGraphDependancyData with data a key
					// do not modify the object !!!!
					if (!reference.ContainsKey(d.Sid))
					{
						reference[d.Sid] = new CompromiseGraphDependancyData();
						reference[d.Sid].Details = new List<CompromiseGraphDependancyDetailData>();
						reference[d.Sid].FQDN = d.FQDN;
						reference[d.Sid].Netbios = d.Netbios;
						reference[d.Sid].Sid = d.Sid;
					}
					var gdData = reference[d.Sid];
					CompromiseGraphDependancyDetailData detail = null;
					foreach (var a in gdData.Details)
					{
						if (a.Typology == sg.Typology)
							detail = a;
					}
					if (detail == null)
					{
						detail = new CompromiseGraphDependancyDetailData()
						{
							Typology = sg.Typology,
							Items = new List<string>(),
						};
						reference[d.Sid].Details.Add(detail);
					}
					detail.NumberOfGroupImpacted++;
					foreach (var item in d.Items)
					{
						if (!detail.Items.Contains(item.Sid))
						{
							detail.Items.Add(item.Sid);
							if (item.Name.Contains("\\"))
								detail.NumberOfResolvedItems++;
							else
								detail.NumberOfUnresolvedItems++;
						}
					}
				}
			}
			data.Dependancies = new List<CompromiseGraphDependancyData>(reference.Values);
			data.Dependancies.Sort((CompromiseGraphDependancyData a, CompromiseGraphDependancyData b)
				=>
				{
					return string.Compare(a.Netbios, b.Netbios);
				});
		}

		private void PrepareAnomalyAnalysisData(CompromiseGraphData data)
		{
			var reference = new Dictionary<CompromiseGraphDataObjectRisk, CompromiseGraphAnomalyAnalysisData>();
			foreach (var sg in data.Data)
			{
				CompromiseGraphAnomalyAnalysisData analysis = null;
				if (!reference.ContainsKey(sg.ObjectRisk))
				{
					analysis = new CompromiseGraphAnomalyAnalysisData()
					{
						ObjectRisk = sg.ObjectRisk,
					};
					reference[sg.ObjectRisk] = analysis;
				}
				else
				{
					analysis = reference[sg.ObjectRisk];
				}
				analysis.NumberOfObjectsScreened++;
				if (sg.CriticalObjectFound)
				{
					analysis.CriticalObjectFound = true;
				}
				if (sg.IndirectMembers.Count > 0)
				{
					if (analysis.MaximumIndirectNumber < sg.IndirectMembers.Count)
						analysis.MaximumIndirectNumber = sg.IndirectMembers.Count;
					analysis.NumberOfObjectsWithIndirect++;
					if (sg.DirectUserMembers.Count > 0)
					{
						int ratio = 100 * sg.IndirectMembers.Count / sg.DirectUserMembers.Count;
						if (ratio > analysis.MaximumDirectIndirectRatio)
							analysis.MaximumDirectIndirectRatio = ratio;
					}
				}


			}
			data.AnomalyAnalysis = new List<CompromiseGraphAnomalyAnalysisData>();
			data.AnomalyAnalysis.AddRange(reference.Values);
			data.AnomalyAnalysis.Sort(
				(CompromiseGraphAnomalyAnalysisData a, CompromiseGraphAnomalyAnalysisData b)
				=>
				{
					return ((int)a.ObjectRisk).CompareTo((int)b.ObjectRisk);
				});
		}

		private void PrepareRiskData(CompromiseGraphData data)
		{
			data.RiskRules = new List<CompromiseGraphRiskRule>();
			var rules = new RuleSet<CompromiseGraphData>();
			foreach (var rule in rules.ComputeRiskRules(data))
			{
				var risk = new CompromiseGraphRiskRule();
				if (rule.Points == 0)
					risk.Achieved = true;
				risk.Points = rule.RuleComputation[0].Score;
				risk.Category = rule.Category;
				risk.Objective = rule.Objective;
				risk.RiskId = rule.RiskId;
				risk.Rationale = rule.Rationale + String.Empty;
				risk.Details = rule.Details;
				risk.ImpactedAssets = new List<CompromiseGraphRiskRuleDetail>();
				var graphRule = rule as CompromiseGraphRule;
				if (graphRule != null)
				{
					foreach (var assetName in graphRule.ImpactedGraph.Keys)
					{
						var asset = graphRule.ImpactedGraph[assetName];
						var impactedAsset = new CompromiseGraphRiskRuleDetail();
						impactedAsset.AssetName = assetName;
						impactedAsset.Details = asset.Details;
						impactedAsset.Rationale = asset.Rationale;
						risk.ImpactedAssets.Add(impactedAsset);
					}
				}
				data.RiskRules.Add(risk);
			}
			data.RiskRules.Sort((CompromiseGraphRiskRule a, CompromiseGraphRiskRule b)
				=>
				{
					int compare = ((int)a.Objective).CompareTo((int)b.Objective);
					if (compare == 0)
					{
						compare = -a.Points.CompareTo(b.Points);
					}
					if (compare == 0)
					{
						compare = a.Rationale.CompareTo(b.Rationale);
					}
					return compare;
				}
			);
		}
		/*
		private void PrepareObjectiveData(CompromiseGraphData data)
		{
			data.Objectives = new List<CompromiseGraphObjective>();
			data.Objectives.Add(new CompromiseGraphObjective()
			{
				Category = RiskRuleCategory.Trusts,
				Objective = "No more than 1 domain can take control of an admin or critical object",
				Score = 100,
				RulesMatched = new List<string>() { "A-TEST" },
			});
			data.Objectives.Add(new CompromiseGraphObjective()
			{
				Category = RiskRuleCategory.Trusts,
				Objective = "No domain can take control of an admin or critical object",
				Score = 100,
			});
			data.Objectives.Add(new CompromiseGraphObjective()
			{
				Category = RiskRuleCategory.Trusts,
				Objective = "No domain can take control of a user defined object",
				Score = 25,
			});
			data.Objectives.Add(new CompromiseGraphObjective()
			{
				Category = RiskRuleCategory.Trusts,
				Objective = "At the exception of a domain declared as an admin domain, no child domain of a forest should have permission on other domains",
				Score = 25,
			});
			bool criticalfound = false;
			foreach (var anomaly in data.AnomalyAnalysis)
			{
				string risk = null;
				int basescore;
				if (anomaly.CriticalObjectFound)
					criticalfound = true;
				switch (anomaly.ObjectRisk)
				{
					case CompromiseGraphDataObjectRisk.Critical:
						risk = "critical";
						basescore = 100;
						break;
					case CompromiseGraphDataObjectRisk.High:
						risk = "high";
						basescore = 80;
						break;
					case CompromiseGraphDataObjectRisk.Medium:
						risk = "medium";
						basescore = 60;
						break;
					default:
						continue;

				}
				data.Objectives.Add(new CompromiseGraphObjective()
				{
					Category = RiskRuleCategory.Anomalies,
					Objective = "No " + risk + " priority object should be available to more than 100 indirect number",
					Score = basescore,
					IsAchieved = anomaly.MaximumIndirectNumber < 100,
				});
				data.Objectives.Add(new CompromiseGraphObjective()
				{
					Category = RiskRuleCategory.Anomalies,
					Objective = "No " + risk + " object should be available to more than 50 indirect number",
					Score = basescore - 10,
					IsAchieved = anomaly.MaximumIndirectNumber < 50,
				});
				data.Objectives.Add(new CompromiseGraphObjective()
				{
					Category = RiskRuleCategory.Anomalies,
					Objective = "No " + risk + " object should be available to more than 10 indirect number",
					Score = basescore - 20,
					IsAchieved = anomaly.MaximumIndirectNumber < 10,
				});
				data.Objectives.Add(new CompromiseGraphObjective()
				{
					Category = RiskRuleCategory.Anomalies,
					Objective = "No " + risk + " object should be available to indirect users at all",
					Score = basescore - 30,
					IsAchieved = anomaly.MaximumIndirectNumber == 0,
				});
			}
			data.Objectives.Add(new CompromiseGraphObjective()
			{
				Category = RiskRuleCategory.Anomalies,
				Objective = "No object should allow Everyone, Authenticated Users, Domain Users or Domain Computers to take control of itself",
				Score = 100,
				IsAchieved = criticalfound,
			});
		}*/

		private void ProduceReportFile(CompromiseGraphData data, CompromiseGraphDataTypology typology, CompromiseGraphDataObjectRisk risk, string description, string name)
		{
			try
			{
				Dictionary<string, string> databaseProperties = storage.GetDatabaseInformation();
				DateTime exportDate = DateTime.Parse(databaseProperties["Date"]);
				Trace.WriteLine("Generating Description:" + description + " Name=" + name);
				int rootNodeId = storage.SearchItem(name);
				if (rootNodeId < 0)
				{
					// do not display error message for schema admin and enterprise admins which are missing on child domains
					if (typology == CompromiseGraphDataTypology.PrivilegedAccount && (name.EndsWith("-519") || name.EndsWith("-518") || name.EndsWith("-498") || name.Equals("S-1-5-32-557")))
						return;
					Trace.WriteLine("Id not found for name=" + name);
					Console.WriteLine("The report " + description + " starting from " + name + " couldn't be built because the object wasn't found");
					return;
				}
				List<int> nodesid = new List<int>();
				Dictionary<int, List<Relation>> links = RetrieveLinks(rootNodeId, nodesid);
				Dictionary<int, Node> chartNodes = storage.RetrieveNodes(nodesid);
				List<int> directUsers = RetrieveDirectUserNodes(rootNodeId, new string[] { "user", "msDS-GroupManagedServiceAccount", "msDS-ManagedServiceAccount" });
				List<int> directComputers = RetrieveDirectUserNodes(rootNodeId, new string[] { "computer" });
				SimplifyGraph(chartNodes, links);
				ComputeDistance(rootNodeId, links, chartNodes);
				var singleCompromiseData = BuildSingleCompromiseGraphData(rootNodeId, chartNodes, links, directUsers);
				singleCompromiseData.Name = name;
				singleCompromiseData.Description = description;
				singleCompromiseData.Typology = typology;
				singleCompromiseData.ObjectRisk = risk;

				BuildUserMembers(singleCompromiseData, directUsers);
				BuildComputerMembers(singleCompromiseData, directComputers);
				BuildIndirectMembers(singleCompromiseData);
				BuildDependancies(data, singleCompromiseData, chartNodes);
				BuildDeletedObjects(data, singleCompromiseData, chartNodes);
				data.Data.Add(singleCompromiseData);
			}
			catch (Exception ex)
			{
				Console.ForegroundColor = ConsoleColor.Red;
				Console.WriteLine("Exception: " + ex.Message);
				Console.WriteLine(ex.StackTrace);
				Trace.WriteLine(ex.Message);
				Trace.WriteLine(ex.StackTrace);
				if (ex.InnerException != null)
				{
					Trace.WriteLine("innerexception: " + ex.InnerException.Message);
				}
			}
		}

		private void BuildDependancies(CompromiseGraphData refData, SingleCompromiseGraphData singleCompromiseData, Dictionary<int, Node> chartNodes)
		{
			var reference = new Dictionary<SecurityIdentifier, SingleCompromiseGraphDependancyData>();
			var domains = storage.GetKnownDomains();
			foreach (var node in chartNodes.Values)
			{
				if (String.Equals(node.Type, "foreignsecurityprincipal", StringComparison.InvariantCultureIgnoreCase))
				{
					// ignore deleted accounts
					if (node.Sid.StartsWith(refData.DomainSid + "-"))
						continue;
					SingleCompromiseGraphDependancyData data;
					var sid = new SecurityIdentifier(node.Sid);
					var domainSid = sid.AccountDomainSid;
					if (domainSid == null)
						continue;
					if (!reference.ContainsKey(domainSid))
					{
						data = new SingleCompromiseGraphDependancyData();
						reference[domainSid] = data;
						data.Sid = domainSid.Value;
						foreach (var domain in domains)
						{
							if (String.Equals(domain.DomainSid.Value, data.Sid, StringComparison.InvariantCultureIgnoreCase))
							{
								data.FQDN = domain.DnsDomainName;
								data.Netbios = domain.NetbiosDomainName;
								break;
							}
						}
						data.Items = new List<SingleCompromiseGraphDependancyMemberData>();
					}
					else
					{
						data = reference[domainSid];
					}
					if (node.Shortname.Contains("\\"))
					{
						if (String.IsNullOrEmpty(data.Netbios))
						{
							data.Netbios = node.Shortname.Split('\\')[0];
						}
						data.NumberOfResolvedItems++;
					}
					else
					{
						data.NumberOfUnresolvedItems++;
					}
					data.Items.Add(new SingleCompromiseGraphDependancyMemberData()
						{
							Name = node.Shortname,
							Sid = node.Sid,
						}
					);
				}
			}
			singleCompromiseData.Dependancies = new List<SingleCompromiseGraphDependancyData>(reference.Values);
			singleCompromiseData.Dependancies.Sort(
				(SingleCompromiseGraphDependancyData a, SingleCompromiseGraphDependancyData b)
					=>
				{
					return String.Compare(a.Netbios, b.Netbios);
				}
			);
		}


		private void BuildDeletedObjects(CompromiseGraphData data, SingleCompromiseGraphData singleCompromiseData, Dictionary<int, Node> chartNodes)
		{
			singleCompromiseData.DeletedObjects = new List<SingleCompromiseGraphDeletedData>();
			foreach (var node in chartNodes.Values)
			{
				if (String.Equals(node.Type, "foreignsecurityprincipal", StringComparison.InvariantCultureIgnoreCase))
				{
					// ignore everything but deleted accounts
					if (node.Sid.StartsWith(data.DomainSid + "-"))
					{
						singleCompromiseData.DeletedObjects.Add(new SingleCompromiseGraphDeletedData()
						{
							Sid = node.Sid,
						}
						);
					}
				}
			}
		}

		private void BuildUserMembers(SingleCompromiseGraphData singleCompromiseData, List<int> directNodes)
		{
			singleCompromiseData.DirectUserMembers = new List<SingleCompromiseGraphUserMemberData>();
			foreach (var id in directNodes)
			{
				var node = storage.RetrieveNode(id);
				var user = BuildMembersUser(node.ADItem);
				singleCompromiseData.DirectUserMembers.Add(user);
			}
		}

		private void BuildComputerMembers(SingleCompromiseGraphData singleCompromiseData, List<int> directNodes)
		{
			singleCompromiseData.DirectComputerMembers = new List<SingleCompromiseGraphComputerMemberData>();
			foreach (var id in directNodes)
			{
				var node = storage.RetrieveNode(id);
				var user = BuildMembersComputer(node.ADItem);
				singleCompromiseData.DirectComputerMembers.Add(user);
			}
		}

		private void BuildIndirectMembers(SingleCompromiseGraphData singleCompromiseData)
		{
			singleCompromiseData.IndirectMembers = new List<SingleCompromiseGraphIndirectMemberData>();
			var map = new Dictionary<int, int>();
			foreach (var link in singleCompromiseData.Links)
			{
				map[link.Source] = link.Target;
			}
			var reference = new Dictionary<int, SingleCompromiseGraphNodeData>();
			foreach (var node in singleCompromiseData.Nodes)
			{
				reference[node.Id] = node;
			}
			foreach (var node in singleCompromiseData.Nodes)
			{
				if (node.Type == "user" && node.Suspicious)
				{
					var user = BuildIndirectMemberUser(singleCompromiseData, node, reference, map);
					singleCompromiseData.IndirectMembers.Add(user);
				}
			}
		}

		private SingleCompromiseGraphIndirectMemberData BuildIndirectMemberUser(SingleCompromiseGraphData singleCompromiseData, SingleCompromiseGraphNodeData node, Dictionary<int, SingleCompromiseGraphNodeData> reference, Dictionary<int, int> map)
		{
			var member = new SingleCompromiseGraphIndirectMemberData();
			member.Name = node.ShortName;
			member.Distance = node.Distance;
			if (node.ADItem.ObjectSid != null)
				member.Sid = node.ADItem.ObjectSid.Value;
			int id = node.Id;
			var currentNode = node;
			var path = new List<string>();
			while (id >= 0 && !(currentNode.Type == "user" && !currentNode.Suspicious))
			{
				path.Add(currentNode.ShortName);
				if (map.ContainsKey(id))
				{
					id = map[id];
					currentNode = reference[id];
				}
				else
					id = -1;
			}
			if (id >= 0)
			{
				path.Add(currentNode.ShortName);
				member.AuthorizedObject = currentNode.ShortName;
			}
			if (path.Count > 4)
			{
				member.Path = path[0] + "->" + path[1] + "->...->" + path[path.Count - 2] + "->" + path[path.Count - 1];
			}
			else
			{
				member.Path = string.Join("->", path.ToArray());
			}
			return member;
		}

		private SingleCompromiseGraphUserMemberData BuildMembersUser(ADItem x)
		{
			var member = new SingleCompromiseGraphUserMemberData();
			member.Name = x.SAMAccountName;
			member.DistinguishedName = x.DistinguishedName;
			member.PwdLastSet = x.PwdLastSet;
			member.LastLogonTimestamp = x.LastLogonTimestamp;
			if ((x.UserAccountControl & 0x00000002) != 0)
			{
			}
			else
			{
				member.IsEnabled = true;
				// last login since 6 months
				if (x.LastLogonTimestamp.AddDays(6 * 31) > DateTime.Now)
				{
					member.IsActive = true;
				}
				else
				{
				}
				if (x.ServicePrincipalName != null && x.ServicePrincipalName.Length > 0)
				{
					member.IsService = true;
					member.SPN = new List<string>(x.ServicePrincipalName);
				}
				if ((x.UserAccountControl & 0x00000010) != 0)
				{
					member.IsLocked = true;
				}
				if ((x.UserAccountControl & 0x00010000) != 0)
				{
					member.DoesPwdNeverExpires = true;
				}
				if ((x.UserAccountControl & 0x00000020) != 0)
				{
					member.IsPwdNotRequired = true;
				}
				// this account is sensitive and cannot be delegated
				if ((x.UserAccountControl & 0x100000) == 0)
				{
					member.CanBeDelegated = true;
				}
				if ((x.UserAccountControl & 0x40000) != 0)
				{
					member.SmartCardRequired = true;
				}
			}
			return member;
		}

		private SingleCompromiseGraphComputerMemberData BuildMembersComputer(ADItem x)
		{
			var member = new SingleCompromiseGraphComputerMemberData();
			member.Name = x.SAMAccountName;
			member.DistinguishedName = x.DistinguishedName;
			member.LastLogonTimestamp = x.LastLogonTimestamp;
			if ((x.UserAccountControl & 0x00000002) != 0)
			{
			}
			else
			{
				member.IsEnabled = true;
				// last login since 6 months
				if (x.LastLogonTimestamp.AddDays(6 * 31) > DateTime.Now)
				{
					member.IsActive = true;
				}
				else
				{
				}
				if (x.ServicePrincipalName != null && x.ServicePrincipalName.Length > 0)
				{
					member.SPN = new List<string>(x.ServicePrincipalName);
				}
				if ((x.UserAccountControl & 0x00000010) != 0)
				{
					member.IsLocked = true;
				}
				// this account is sensitive and cannot be delegated
				if ((x.UserAccountControl & 0x100000) == 0)
				{
					member.CanBeDelegated = true;
				}
			}
			return member;
		}

		#region node relation links
		private void ComputeDistance(int startid, Dictionary<int, List<Relation>> relations, Dictionary<int, Node> nodes)
		{
			List<int> idtoadd = new List<int>();
			List<int> idtoenumerate = null;
			List<int> knownid = new List<int>();
			int distance = 0;
			idtoadd.Add(startid);
			nodes[startid].Distance = 0;
			while (true)
			{
				idtoenumerate = idtoadd;
				idtoadd = new List<int>();
				foreach (int currentid in idtoenumerate)
				{
					if (relations.ContainsKey(currentid))
					{
						foreach (Relation relation in relations[currentid])
						{
							if (!knownid.Contains(relation.ToId))
							{
								idtoadd.Add(relation.ToId);
								knownid.Add(relation.ToId);
							}
						}
					}
				}
				if (idtoadd.Count == 0)
				{
					break;
				}
				distance++;
				foreach (int nodeid in idtoadd)
				{
					nodes[nodeid].Distance = distance;
				}
			}
		}

		private List<int> RetrieveDirectUserNodes(int id, IEnumerable<string> linkTypes)
		{
			List<int> directUserNodes = new List<int>();
			List<int> input = new List<int>() { id };
			List<int> output = new List<int>();
			var rootNode = storage.RetrieveNode(id);
			foreach (string linkType in linkTypes)
			{
				if (rootNode.Type == linkType)
				{
					directUserNodes.Add(id);
					break;
				}
			}
			while (input.Count > 0)
			{
				List<Relation> data = storage.SearchRelations(input, input);
				foreach (Relation link in data)
				{
					if (link.Hint.Contains(RelationType.group_member.ToString()) ||
						link.Hint.Contains(RelationType.primary_group_member.ToString()))
					{
						output.Add(link.ToId);
						if (!directUserNodes.Contains(link.ToId))
						{
							var node = storage.RetrieveNode(link.ToId);
							foreach (string linkType in linkTypes)
							{
								if (node.Type == linkType)
								{
									directUserNodes.Add(link.ToId);
									break;
								}
							}
						}
					}
				}
				input.Clear();
				input.AddRange(output);
				output.Clear();
			}
			return directUserNodes;
		}

		private Dictionary<int, List<Relation>> RetrieveLinks(int id, List<int> nodesid)
		{
			Dictionary<int, List<Relation>> output = new Dictionary<int, List<Relation>>();
			List<int> input = new List<int>() { id };
			nodesid.Add(id);
			int depth = 1;
			while (true)
			{
				List<Relation> data = storage.SearchRelations(input, nodesid);
				if (data.Count > 0)
				{
					input.Clear();
					foreach (Relation link in data)
					{
						if (!output.ContainsKey(link.FromId))
						{
							output[link.FromId] = new List<Relation>();
						}
						output[link.FromId].Add(link);
						if (!nodesid.Contains(link.ToId))
						{
							nodesid.Add(link.ToId);
							var node = storage.RetrieveNode(link.ToId);
							if (!IsStopNode(node))
								input.Add(link.ToId);
						}
					}
					if (nodesid.Count > MaxNodes)
					{
						Trace.WriteLine("The report reached the maximum of nodes allowed (" + nodesid.Count + " versus MaxNodes=" + MaxNodes + ")");
						break;
					}
					if (depth > MaxDepth)
					{
						Trace.WriteLine("The report reached the maximum of depth allowed (" + depth + " versus MaxDepth=" + MaxDepth + ")");
						break;
					}
				}
				else
				{
					break;
				}
				depth++;
			}
			return output;
		}

		private bool IsStopNode(Node node)
		{
			if ((!String.IsNullOrEmpty(node.Sid) && stopNodes.Contains(node.Sid))
				|| (node.ADItem != null && !String.IsNullOrEmpty(node.ADItem.DistinguishedName) && stopNodes.Contains(node.ADItem.DistinguishedName)))
			{
				return true;
			}
			return false;
		}

		private void PrepareStopNodes(GraphObjectReference ObjectReference)
		{
			stopNodes.Clear();
			foreach (var typology in ObjectReference.Objects.Keys)
			{
				foreach (var obj in ObjectReference.Objects[typology])
				{
					stopNodes.Add(obj.Name);
				}
			}
		}

		void SimplifyGraph(Dictionary<int, Node> nodes, Dictionary<int, List<Relation>> links)
		{
			// remove file node from GPO when there is nothing else than files connected to
			List<int> nodesToRemove = new List<int>();
			foreach (Node node in nodes.Values)
			{
				if (node.Type == "grouppolicycontainer")
				{
					Trace.WriteLine("Analysing GPO file node for " + node.Name);
					bool FileOnly = true;
					List<int> nodesExplored = new List<int>();
					List<int> nodesToExplore = new List<int>();
					nodesToExplore.Add(node.Id);
					// check for anything else than a file
					while (nodesToExplore.Count > 0)
					{
						int nodeExplored = nodesToExplore[0];
						nodesToExplore.Remove(nodeExplored);
						if (nodesExplored.Contains(nodeExplored))
							continue;
						nodesExplored.Add(nodeExplored);
						if (nodes[nodeExplored].Type != "container"
							&& nodes[nodeExplored].Type != "configuration"
							&& nodes[nodeExplored].Type != "foreignsecurityprincipal" && !node.Name.Contains("CN=WellKnown Security Principals,CN=Configuration,"))
						{
							if (node.Id != nodeExplored && nodes[nodeExplored].Type != "file")
							{
								FileOnly = false;
								Trace.WriteLine("Stopped because suspicious node found:" + nodes[nodeExplored].Name);
								break;
							}
							foreach (int key in links.Keys)
							{
								List<Relation> relations = links[key];
								foreach (Relation relation in relations)
								{
									if (relation.FromId == nodeExplored)
									{
										// we checked nodes because the graph can be cut
										if (!nodesExplored.Contains(relation.ToId) && nodes.ContainsKey(relation.ToId))
										{
											nodesToExplore.Add(relation.ToId);
										}
									}
								}
							}
						}
					}
					if (FileOnly)
					{
						Trace.WriteLine("Removing GPO file node for " + node.Name);
						foreach (int id in nodesExplored)
						{
							if (!nodesToRemove.Contains(id) && node.Id != id && nodes[id].Type == "file")
								nodesToRemove.Add(id);
						}
					}

				}
			}
			// the list of Node to remove is:nodesExplored
			foreach (int nodeToRemove in nodesToRemove)
			{
				Trace.WriteLine("Simplying graph: removing node " + nodes[nodeToRemove].Name);
				nodes.Remove(nodeToRemove);
				links.Remove(nodeToRemove);
				List<int> entryToRemoveInDictionnary = new List<int>();
				foreach (int key in links.Keys)
				{
					List<Relation> relations = links[key];
					for (int i = relations.Count - 1; i >= 0; i--)
					{
						Relation relation = relations[i];
						if (nodesToRemove.Contains(relation.ToId))
						{
							relations.RemoveAt(i);
						}
					}
					if (relations.Count == 0)
					{
						entryToRemoveInDictionnary.Add(key);
					}
				}
				foreach (int key in entryToRemoveInDictionnary)
				{
					links.Remove(key);
				}
			}
		}

		#endregion node relation links

		#region data file

		private SingleCompromiseGraphData BuildSingleCompromiseGraphData(int rootNodeId, Dictionary<int, Node> nodes, Dictionary<int, List<Relation>> links, List<int> directNodes)
		{
			var data = new SingleCompromiseGraphData();
			var idconversiontable = new Dictionary<int, int>();

			// START OF NODES

			data.Nodes = new List<SingleCompromiseGraphNodeData>();

			// it is important to put the root node as the first node for correct display
			int nodenumber = 0;
			Node rootNode = nodes[rootNodeId];
			data.Nodes.Add(new SingleCompromiseGraphNodeData()
			{
				Id = nodenumber,
				Name = rootNode.Name,
				Type = rootNode.Type,
				ShortName = rootNode.Shortname,
				Distance = 0,
			});
			idconversiontable[rootNode.Id] = nodenumber++;

			foreach (Node node in nodes.Values)
			{
				if (node.Id == rootNodeId)
					continue;
				if (String.Equals(node.Type, "foreignsecurityprincipal", StringComparison.OrdinalIgnoreCase))
				{
					if (String.Equals(node.Sid, "S-1-5-11", StringComparison.OrdinalIgnoreCase))
					{
						data.Nodes.Add(new SingleCompromiseGraphNodeData()
						{
							Id = nodenumber,
							Name = node.Name,
							Type = node.Type,
							ShortName = "Authenticated Users",
							Distance = node.Distance,
							Critical = true,
							ADItem = node.ADItem,
						});
						// unusual except when found on pre win2k group
						if (!String.Equals(rootNode.Sid, "S-1-5-32-554", StringComparison.OrdinalIgnoreCase))
							data.CriticalObjectFound = true;
						idconversiontable[node.Id] = nodenumber++;
						continue;
					}
					if (String.Equals(node.Sid, "S-1-1-0", StringComparison.OrdinalIgnoreCase))
					{
						data.Nodes.Add(new SingleCompromiseGraphNodeData()
						{
							Id = nodenumber,
							Name = node.Name,
							Type = node.Type,
							ShortName = "Everyone",
							Distance = node.Distance,
							Critical = true,
							ADItem = node.ADItem,
						});
						data.CriticalObjectFound = true;
						idconversiontable[node.Id] = nodenumber++;
						continue;
					}
				}
				bool domainUsersFound = (node.Type == "foreignsecurityprincipal" && node.Name.EndsWith("-513"));
				if (domainUsersFound)
					data.CriticalObjectFound = true;
				data.Nodes.Add(new SingleCompromiseGraphNodeData()
				{
					Id = nodenumber,
					Name = node.Name,
					Type = node.Type,
					ShortName = node.Shortname,
					Distance = node.Distance,
					Suspicious = (node.Type == "user" && !directNodes.Contains(node.Id)),
					Critical = domainUsersFound,
					ADItem = node.ADItem,
				});
				idconversiontable[node.Id] = nodenumber++;
			}
			// END OF NODES

			// defensive programming: check for data consistency
			foreach (int key in links.Keys)
			{
				List<Relation> link = links[key];
				foreach (Relation detail in link)
				{
					if (!idconversiontable.ContainsKey(detail.ToId))
					{
						Trace.WriteLine("Inconsistancy: node missing: Id=" + detail.ToId);
					}
					if (!idconversiontable.ContainsKey(detail.FromId))
					{
						Trace.WriteLine("Inconsistancy: node missing: Id=" + detail.FromId);
					}
				}
			}

			// START LINKS
			data.Links = new List<SingleCompromiseGraphLinkData>();

			foreach (int key in links.Keys)
			{
				List<Relation> link = links[key];
				foreach (Relation detail in link)
				{
					data.Links.Add(new SingleCompromiseGraphLinkData()
					{
						Source = idconversiontable[detail.ToId],
						Target = idconversiontable[detail.FromId],
						Hints = detail.Hint,
					});
				}
			}
			// END OF LINKS
			return data;
		}
		#endregion data file

	}
}
