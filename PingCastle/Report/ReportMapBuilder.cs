//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Data;
using PingCastle.Healthcheck;
using PingCastle.template;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace PingCastle.Report
{
    public class ReportHealthCheckMapBuilder : ReportBase
    {
        protected PingCastleReportCollection<HealthcheckData> Report = null;
        protected OwnerInformationReferences EntityData = null;

        public ReportHealthCheckMapBuilder(PingCastleReportCollection<HealthcheckData> consolidation, OwnerInformationReferences ownerInformationReferences)
        {
            this.Report = consolidation;
            EntityData = ownerInformationReferences;
            FullNodeMap = true;
        }
        public ReportHealthCheckMapBuilder(PingCastleReportCollection<HealthcheckData> consolidation, ADHealthCheckingLicense license) : this(consolidation, (OwnerInformationReferences)null)
        {
            Brand(license);
        }


        public delegate void GraphLogging(string message);

        public GraphLogging Log { get; set; }

        public IMigrationChecker migrationChecker { get; set; }

        public string CenterDomainForSimpliedGraph { get; set; }

        public bool FullNodeMap { get; set; }

        // build a model & cache it
        GraphNodeCollection _nodes;
        protected GraphNodeCollection Nodes
        {
            get
            {
                if (_nodes == null)
                    _nodes = GraphNodeCollection.BuildModel(Report, EntityData);
                return _nodes;
            }
        }

        protected override void GenerateTitleInformation()
        {
            Add("PingCastle AD Map ");
            Add(DateTime.Now.ToString("yyyy-MM-dd"));
            Add(" (");
            Add(Nodes.Count);
            Add(" domains)");
        }

        protected override void ReferenceJSAndCSS()
        {
            AddStyle(TemplateManager.LoadReportMapBuilderCss());
            AddStyle(TemplateManager.LoadVisCss());
            AddScript(TemplateManager.LoadVisJs());
            AddScript(TemplateManager.LoadReportBaseJs());
            AddScript(TemplateManager.LoadReportMapBuilderJs());
        }

        protected override void GenerateBodyInformation()
        {
            GenerateNavigation("Active Directory map " + (FullNodeMap ? "full" : "simple"), null);
            GenerateAbout();
            Add(@"
<noscript>
	<div class=""alert alert-alert"">
		<p><strong>This report requires javascript.</strong></p>
	</div>
</noscript>
<!-- Modal -->
<div class=""modal"" id=""loadingModal"" role=""dialog"">
    <div class=""modal-dialog"">
        <!-- Modal content-->
        <div class=""modal-content"">
            <div class=""modal-header"">
                <h4 class=""modal-title"">Loading ...</h4>
            </div>
            <div class=""modal-body"">
                <div class=""progress"">
                    <div class=""progress-bar"" role=""progressbar"" aria-valuenow=""0"" aria-valuemin=""0"" aria-valuemax=""100"">
                        0%
                    </div>
                </div>
            </div>
        </div>

    </div>
</div>
<div id=""mynetwork"" class=""network-area""></div>

<div class=""legend_carto"">
    Legend: <br>
    <i class=""legend_criticalscore"">&nbsp;</i> score=100<br>
    <i class=""legend_superhighscore"">&nbsp;</i> score &lt; 100<br>
    <i class=""legend_highscore"">&nbsp;</i> score &lt; 70<br>
    <i class=""legend_mediumscore"">&nbsp;</i> score &lt; 50<br>
    <i class=""legend_lowscore"">&nbsp;</i> score &lt; 30<br>
    <i class=""legend_unknown"">&nbsp;</i> score unknown
</div>
");
        }

        protected override void GenerateFooterInformation()
        {
            AddLine(@"<script type=""application/json"" data-pingcastle-selector=""Data"">");
            if (FullNodeMap)
            {
                AddLine(GenerateJsonFileFull(migrationChecker));
            }
            else
            {
                AddLine(GenerateJsonFileSimple(CenterDomainForSimpliedGraph));
            }
            AddLine(@"</script>");
            AddLine(@"<script type=""application/json"" data-pingcastle-selector=""FullNodeMap"">");
            if (FullNodeMap)
                Add("true");
            else
                Add("false");
            AddLine(@"</script>");
        }


        #region json file

        public string GenerateJsonFileFull(IMigrationChecker migrationChecker)
        {
            Dictionary<int, int> idconversiontable = new Dictionary<int, int>();
            StringBuilder sb = new StringBuilder();
            sb.Append("{");
            // START OF NODES

            sb.Append("  \"nodes\": [");
            // it is important to put the root node as the first node for correct display
            int nodenumber = 0;
            bool firstnode = true;
            foreach (GraphNode node in Nodes)
            {
                if (!firstnode)
                {
                    sb.Append("    },");
                }
                else
                {
                    firstnode = false;
                }
                sb.Append("    {");
                sb.Append("      \"id\": " + nodenumber + ",");
                var nodeShortName = !string.IsNullOrEmpty(node.Domain.DomainNetBIOS) ? node.Domain.DomainNetBIOS : (node.Domain.DomainName.Split('.')[0]);
                sb.Append("      \"shortname\": \"" + ReportHelper.EscapeJsonString(ReportHelper.Encode(nodeShortName)) + "\"");
                if (node.IsPartOfARealForest())
                {
                    sb.Append("      ,\"forest\": \"" + ReportHelper.EscapeJsonString(ReportHelper.Encode(node.Forest.DomainName)) + "\"");
                }
                if (node.IsPotentiallyRemoved)
                {
                    sb.Append("      ,\"potentiallyremoved\": 1");
                }
                var entity = node.Entity;
                if (entity != null)
                {
                    sb.Append(entity.GetJasonOutput());
                }
                HealthcheckData data = node.HealthCheckData;
                sb.Append("      ,\"name\": \"" + ReportHelper.EscapeJsonString(ReportHelper.Encode(node.Domain.DomainName)) + "\"");
                if (data != null)
                {
                    sb.Append("      ,\"score\": " + data.GlobalScore);
                    sb.Append("      ,\"maturityLevel\": " + data.MaturityLevel);
                    sb.Append("      ,\"staleObjectsScore\": " + data.StaleObjectsScore);
                    sb.Append("      ,\"privilegiedGroupScore\": " + data.PrivilegiedGroupScore);
                    sb.Append("      ,\"trustScore\": " + data.TrustScore);
                    sb.Append("      ,\"anomalyScore\": " + data.AnomalyScore);
                    if (data.UserAccountData != null)
                        sb.Append("      ,\"activeusers\": " + data.UserAccountData.NumberActive);
                    if (data.ComputerAccountData != null)
                        sb.Append("      ,\"activecomputers\": " + data.ComputerAccountData.NumberActive);
                }
                sb.Append("      ,\"dist\": null");
                idconversiontable[node.Id] = nodenumber++;
            }
            if (Nodes.Count > 0)
            {
                sb.Append("    }");
            }
            sb.Append("  ],");
            // END OF NODES
            // START LINKS
            sb.Append("  \"links\": [");
            // avoid a final ","
            bool absenceOfLinks = true;
            // subtility: try to regroup 2 links at one if all the properties match
            // SkipLink contains the edge to ignore
            List<GraphEdge> SkipLink = new List<GraphEdge>();
            // foreach edge
            foreach (GraphNode node in Nodes)
            {
                foreach (GraphEdge edge in node.Trusts.Values)
                {

                    if (SkipLink.Contains(edge))
                        continue;
                    // for unidirectional trusts
                    // keep only the remote part of the trust. SID Filtering is unknown (avoid evaluating SID Filtering when no value is available)
                    if (edge.TrustDirection == 2 && edge.IsAuthoritative == false)
                        continue;
                    // keep only the reception of the trust. SID Filtering status is sure
                    if (edge.TrustDirection == 1 && edge.Destination.Trusts[edge.Source.Domain].IsAuthoritative == true)
                        continue;
                    // trying to simplify bidirectional trusts
                    bool isBidirectional = false;
                    if (edge.IsEquivalentToReverseEdge(migrationChecker))
                    {
                        GraphEdge reverseEdge = edge.Destination.Trusts[edge.Source.Domain];
                        // keep only one of the two part of the bidirectional trust
                        SkipLink.Add(reverseEdge);
                        isBidirectional = true;
                    }
                    if (!absenceOfLinks)
                    {
                        sb.Append("    },");
                    }
                    else
                    {
                        absenceOfLinks = false;
                    }
                    sb.Append("    {");
                    if (edge.TrustDirection == 2)
                    {
                        sb.Append("      \"source\": " + idconversiontable[edge.Destination.Id] + ",");
                        sb.Append("      \"target\": " + idconversiontable[edge.Source.Id] + ",");
                    }
                    else
                    {
                        sb.Append("      \"source\": " + idconversiontable[edge.Source.Id] + ",");
                        sb.Append("      \"target\": " + idconversiontable[edge.Destination.Id] + ",");
                    }
                    // blue: 25AEE4
                    // orange: FA9426
                    string sidFiltering = edge.GetSIDFilteringStatus(migrationChecker);
                    if (!edge.IsActive)
                    {
                        // purple
                        sb.Append("      \"color\": \"#A856AA\",");
                    }
                    else
                    {
                        switch (sidFiltering)
                        {
                            case "Remote":
                                // yellow
                                sb.Append("      \"color\": \"#FDC334\",");
                                break;
                            case "Migration":
                                // blue
                                sb.Append("      \"color\": \"#25AEE4\",");
                                break;
                            case "No":
                                // red
                                sb.Append("      \"color\": \"#E75351\",");
                                break;
                            case "Yes":
                                // green
                                sb.Append("      \"color\": \"#74C25C\",");
                                break;
                        }
                    }
                    if (isBidirectional)
                    {
                        sb.Append("      \"type\": \"double\",");
                    }
                    sb.Append("      \"rels\": [\"");
                    sb.Append("Attributes=" + edge.GetTrustAttributes() + ",");
                    if (edge.CreationDate != DateTime.MinValue)
                    {
                        sb.Append("CreationDate=" + edge.CreationDate.ToString("yyyy-MM-dd") + ",");
                    }
                    sb.Append("SIDFiltering=" + sidFiltering);
                    sb.Append((edge.IsActive ? null : ",Inactive"));
                    sb.Append("\"]");

                }
            }
            if (!absenceOfLinks)
            {
                sb.Append("    }");
            }
            sb.Append("  ]");
            // END OF LINKS
            sb.Append("}");
            return sb.ToString();
        }

        public string GenerateJsonFileSimple(string domainToCenter)
        {
            int coveredNodesCount;
            return GenerateJsonFileSimple(domainToCenter, out coveredNodesCount);
        }

        private string GenerateJsonFileSimple(string domainToCenter,
                                            out int coveredNodesCount)
        {
            GraphNode center = null;
            StringBuilder sb = new StringBuilder();
            if (String.IsNullOrEmpty(domainToCenter))
            {
                Trace.WriteLine("finding the center domain");
                // find the domain with the most links
                int max = 0;
                foreach (var nodeToInvestigate in Nodes)
                {
                    if (nodeToInvestigate.Trusts.Count > max)
                    {
                        max = nodeToInvestigate.Trusts.Count;
                        center = nodeToInvestigate;
                    }
                }
                if (center == null)
                {
                    string output = null;
                    Trace.WriteLine("no domain found");
                    sb.Append("{");
                    sb.Append("  \"name\": \"No domain found\"\r\n");
                    sb.Append("}");
                    coveredNodesCount = 0;
                    return output;
                }
                if (Log != null)
                {
                    Log.Invoke("Simplified graph: automatic center on " + center);
                    Log.Invoke("Simplified graph: you can change this with --center-on <domain>");
                }
            }
            else
            {
                center = Nodes.GetDomain(domainToCenter.ToLowerInvariant());
                if (center == null)
                {
                    string output = null;
                    Trace.WriteLine(domainToCenter + " not found");
                    sb.Append("{");
                    sb.Append("  \"name\": \"" + domainToCenter + "\"\r\n");
                    sb.Append("}");
                    if (Log != null)
                    {
                        Log.Invoke("Simplified graph: domain " + domainToCenter + " not found.");
                    }
                    coveredNodesCount = 1;
                    return output;
                }
            }
            GraphNode newCentralNode = GenerateSimplifiedGraph(Nodes, center);
            coveredNodesCount = CountSimplifiedNodes(newCentralNode); if (Log != null)
                if (Log != null)
                {
                    Log.Invoke("Simplified graph: contains " + coveredNodesCount + " nodes on a total of " + Nodes.Count);
                }
            GenerateSimplifiedJason(sb, newCentralNode);
            return sb.ToString();
        }

        // make a clone of all GraphNode except that only a few GraphEdge are kept
        // remove all uneeded GraphEdge to have only one GraphEdge between 2 GraphNodes (direct or indirect link)
        private GraphNode GenerateSimplifiedGraph(GraphNodeCollection nodes, GraphNode centralNode)
        {
            List<GraphNode> nodeAlreadyExamined = new List<GraphNode>();

            GraphNode output = GraphNode.CloneWithoutTrusts(centralNode);

            Dictionary<DomainKey, GraphNode> graph = new Dictionary<DomainKey, GraphNode>();
            graph.Add(output.Domain, output);

            List<GraphNode> nodesToExamine = new List<GraphNode>();
            nodesToExamine.Add(centralNode);
            // proceed layer by layer
            for (int currentLevel = 0; ; currentLevel++)
            {
                List<GraphNode> nodesToExamineForNextLevel = new List<GraphNode>();
                // this first iteration is important
                // it avoid a recursing exploration
                foreach (GraphNode nodeToExamine in nodesToExamine)
                {
                    nodeAlreadyExamined.Add(nodeToExamine);
                }
                foreach (GraphNode nodeToExamine in nodesToExamine)
                {
                    foreach (GraphEdge edge in nodeToExamine.Trusts.Values)
                    {
                        if (!nodeAlreadyExamined.Contains(edge.Destination)
                            && !nodesToExamine.Contains(edge.Destination)
                            && !nodesToExamineForNextLevel.Contains(edge.Destination))
                        {
                            // make a clone and add one GraphEdge
                            nodesToExamineForNextLevel.Add(edge.Destination);
                            graph.Add(edge.Destination.Domain, GraphNode.CloneWithoutTrusts(edge.Destination));
                            GraphEdge newEdge = new GraphEdge(graph[nodeToExamine.Domain], graph[edge.Destination.Domain], null, false);
                            graph[nodeToExamine.Domain].Trusts.Add(edge.Destination.Domain, newEdge);
                        }
                    }
                }
                if (nodesToExamineForNextLevel.Count == 0)
                    break;
                nodesToExamine = nodesToExamineForNextLevel;
            }
            return output;
        }

        private int CountSimplifiedNodes(GraphNode centralNode)
        {
            int num = 1;
            foreach (GraphEdge edge in centralNode.Trusts.Values)
            {
                num += CountSimplifiedNodes(edge.Destination);
            }
            return num;
        }

        private void GenerateSimplifiedJason(StringBuilder sb, GraphNode node)
        {
            sb.Append("{");
            sb.Append("  \"name\": \"" + ReportHelper.EscapeJsonString(node.Domain.DomainName) + "\"\r\n");
            var nodeShortName = !string.IsNullOrEmpty(node.Domain.DomainNetBIOS) ? node.Domain.DomainNetBIOS : (node.Domain.DomainName.Split('.')[0]);
            sb.Append("  ,\"shortname\": \"" + ReportHelper.EscapeJsonString(nodeShortName) + "\"\r\n");
            if (node.Forest != null && node.Forest != node.Domain)
            {
                sb.Append("      ,\"forest\": \"" + ReportHelper.EscapeJsonString(node.Forest.DomainName) + "\"");
            }
            if (node.IsPotentiallyRemoved)
            {
                sb.Append("      ,\"potentiallyremoved\": 1");
            }
            HealthcheckData data = node.HealthCheckData;
            if (data != null)
            {
                sb.Append("      ,\"score\": " + data.GlobalScore);
                sb.Append("      ,\"maturityLevel\": " + data.MaturityLevel);
                sb.Append("      ,\"staleObjectsScore\": " + data.StaleObjectsScore);
                sb.Append("      ,\"privilegiedGroupScore\": " + data.PrivilegiedGroupScore);
                sb.Append("      ,\"trustScore\": " + data.TrustScore);
                sb.Append("      ,\"anomalyScore\": " + data.AnomalyScore);
            }
            var entity = node.Entity;
            if (entity != null)
            {
                sb.Append(entity.GetJasonOutput());
            }
            if (node.Trusts.Count > 0)
            {
                sb.Append("      ,\"children\": [\r\n");
                int numChildren = 0;
                foreach (GraphEdge edge in node.Trusts.Values)
                {
                    if (numChildren != 0)
                    {
                        sb.Append(",\r\n");
                    }
                    GenerateSimplifiedJason(sb, edge.Destination);
                    numChildren++;
                }
                sb.Append("      ]\r\n");
            }
            sb.Append("}");
        }


        public string GenerateJsonFileChordDiagram(IMigrationChecker migrationChecker)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("[");
            bool firstnode = true;
            foreach (GraphNode node in Nodes)
            {
                if (!firstnode)
                {
                    sb.AppendLine(",");
                }
                else
                {
                    firstnode = false;
                }
                sb.Append("    {");
                sb.Append("      \"name\": \"" + ReportHelper.EscapeJsonString(node.Domain.DomainName) + "\"");
                if (node.IsPotentiallyRemoved)
                {
                    sb.Append("      ,\"potentiallyremoved\": 1");
                }
                var entity = node.Entity;
                if (entity != null)
                {
                    sb.Append(entity.GetJasonOutput());
                }
                HealthcheckData data = node.HealthCheckData;
                if (data != null)
                {
                    sb.Append("      ,\"score\": " + data.GlobalScore);
                    sb.Append("      ,\"maturityLevel\": " + data.MaturityLevel);
                    sb.Append("      ,\"staleObjectsScore\": " + data.StaleObjectsScore);
                    sb.Append("      ,\"privilegiedGroupScore\": " + data.PrivilegiedGroupScore);
                    sb.Append("      ,\"trustScore\": " + data.TrustScore);
                    sb.Append("      ,\"anomalyScore\": " + data.AnomalyScore);
                    if (data.UserAccountData != null)
                        sb.Append("      ,\"activeusers\": " + data.UserAccountData.NumberActive);
                    if (data.ComputerAccountData != null)
                        sb.Append("      ,\"activecomputers\": " + data.ComputerAccountData.NumberActive);
                }
                sb.Append("      ,\"trusts\": [");
                bool firstTrust = true;
                foreach (var edge in node.Trusts.Values)
                {
                    var destination = edge.Destination;
                    if (!firstTrust)
                    {
                        sb.Append(",");
                    }
                    else
                    {
                        firstTrust = false;
                    }
                    sb.Append("    {");
                    sb.Append("\"name\": \"");
                    sb.Append(ReportHelper.EscapeJsonString(destination.Domain.DomainName));
                    sb.Append("\"");
                    var entity2 = destination.Entity;
                    if (entity2 != null)
                    {
                        sb.Append(entity2.GetJasonOutput());
                    }
                    sb.Append("}");
                }
                sb.Append("]");
                sb.Append("}");

            }

            sb.AppendLine("]");
            return sb.ToString();
        }

        #endregion json file
    }
}
