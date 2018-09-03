//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Data;
using PingCastle.Database;
using PingCastle.Healthcheck;
using PingCastle.template;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text;

namespace PingCastle.Reporting
{
	public class ReportGenerator
	{
		private int MaxDepth;
		private int MaxNodes;
		private IDataStorage storage;

		public ReportGenerator(IDataStorage storage, int MaxDepth, int MaxNodes)
		{
			this.MaxDepth = MaxDepth;
			this.MaxNodes = MaxNodes;
			this.storage = storage;
		}

		public static bool JasonOnly { get; set; }


		public CompromiseGraphData GenerateReport(List<string> AdditionalNames)
		{
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
			data.Data = new List<SingleCompromiseGraphData>();

			ProduceReportFile(data, "Account Operator", "S-1-5-32-548");
			ProduceReportFile(data, "Administrators", "S-1-5-32-544");
			ProduceReportFile(data, "Domain Administrators", data.DomainSid + "-512");
			ProduceReportFile(data, "Enterprise Administrators", data.DomainSid + "-519");
			ProduceReportFile(data, "Schema Administrators", data.DomainSid + "-518");
			ProduceReportFile(data, "Administrator", data.DomainSid + "-500");
			ProduceReportFile(data, "Backup Operators", "S-1-5-32-551");
			ProduceReportFile(data, "Certificate Publishers", data.DomainSid + "-517");
			ProduceReportFile(data, "Certificate Operators", "S-1-5-32-569");
			ProduceReportFile(data, "Domain Controllers", data.DomainSid + "-516");
			ProduceReportFile(data, "Enterprise Read Only Domain Controllers", data.DomainSid + "-498");
			ProduceReportFile(data, "Group Policy Creator Owners", data.DomainSid + "-520");
			ProduceReportFile(data, "Incoming Forest Trust Builders", "S-1-5-32-557");
			ProduceReportFile(data, "Krbtgt account", data.DomainSid + "-502");
			ProduceReportFile(data, "Network Operators", "S-1-5-32-556");
			ProduceReportFile(data, "Pre-Windows 2000 Compatible Access", "S-1-5-32-554");
			ProduceReportFile(data, "Print Operators", "S-1-5-32-550");
			ProduceReportFile(data, "Domain Root", data.DomainSid);
			ProduceReportFile(data, "Read Only Domain Controllers", data.DomainSid + "-521");
			ProduceReportFile(data, "Server Operators", "S-1-5-32-549");
			foreach (string name in AdditionalNames)
			{
				ProduceReportFile(data, name, name, true);
			}
			return data;
		}

		private void ProduceReportFile(CompromiseGraphData data, string description, string name, bool onDemand = false)
		{
			try
			{
				Dictionary<string, string> databaseProperties = storage.GetDatabaseInformation();
				DateTime exportDate = DateTime.Parse(databaseProperties["Date"]);
				Trace.WriteLine("Generating Description:" + description + " Name=" + name);
				int rootNodeId = storage.SearchItem(name);
				if (rootNodeId < 0)
				{
					Trace.WriteLine("Id not found for name=" + name);
					Console.WriteLine("The report " + description + " starting from " + name + " couldn't be built because the object wasn't found");
					return;
				}
				List<int> nodesid = new List<int>();
				Dictionary<int, List<Relation>> links = RetrieveLinks(rootNodeId, nodesid);
				Dictionary<int, Node> nodes = storage.RetrieveNodes(nodesid);
				SimplifyGraph(nodes, links);
				ComputeDistance(rootNodeId, links, nodes);
				var singleCompromiseData = BuildSingleCompromiseGraphData(rootNodeId, nodes, links);
				singleCompromiseData.Name = name;
				singleCompromiseData.Description = description;
				singleCompromiseData.OnDemandAnalysis = onDemand;
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

		private Dictionary<int, List<Relation>> RetrieveLinks(int id, List<int> nodesid)
		{
			Dictionary<int, List<Relation>> output = new Dictionary<int, List<Relation>>();
			List<int> input = new List<int>();
			input.Add(id);
			nodesid.Add(id);
			int depth = 1;
			while (true)
			{
				List<Relation> data = storage.SearchRelations(input, nodesid, false);
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

		private SingleCompromiseGraphData BuildSingleCompromiseGraphData(int rootNodeId, Dictionary<int, Node> nodes, Dictionary<int, List<Relation>> links)
		{
			var data = new SingleCompromiseGraphData();
			Dictionary<int, int> idconversiontable = new Dictionary<int, int>();

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
					if (String.Equals(node.Shortname, "S-1-5-11", StringComparison.OrdinalIgnoreCase))
					{
						data.Nodes.Add(new SingleCompromiseGraphNodeData()
						{
							Id = nodenumber,
							Name = node.Name,
							Type = node.Type,
							ShortName = "Authenticated Users",
							Distance = node.Distance,
						});
						data.UnusualGroup = true;
						idconversiontable[node.Id] = nodenumber++;
						continue;
					}
					if (String.Equals(node.Shortname, "S-1-1-0", StringComparison.OrdinalIgnoreCase))
					{
						data.Nodes.Add(new SingleCompromiseGraphNodeData()
						{
							Id = nodenumber,
							Name = node.Name,
							Type = node.Type,
							ShortName = "Everyone",
							Distance = node.Distance,
						});
						data.UnusualGroup = true;
						idconversiontable[node.Id] = nodenumber++;
						continue;
					}
				}
				data.Nodes.Add(new SingleCompromiseGraphNodeData()
				{
					Id = nodenumber,
					Name = node.Name,
					Type = node.Type,
					ShortName = node.Shortname,
					Distance = node.Distance,
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
