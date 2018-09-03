//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.template;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using System.Text;

namespace PingCastle.Healthcheck
{
    public class HealthCheckReportMapBuilder : HealthCheckReportBase
    {
		protected HealthcheckDataCollection consolidation = null;
		protected OwnerInformationReferences EntityData = null;

		public HealthCheckReportMapBuilder(HealthcheckDataCollection consolidation, OwnerInformationReferences ownerInformationReferences)
        {
            this.consolidation = consolidation;
			EntityData = ownerInformationReferences;
			FullNodeMap = true;
        }
		public HealthCheckReportMapBuilder(HealthcheckDataCollection consolidation) : this(consolidation, null)
		{
		}


        public delegate void GraphLogging(string message);

        public GraphLogging Log { get; set; }

        public static bool JasonOnly { get; set; }

        public MigrationChecker migrationChecker { get; set; }

		public string CenterDomainForSimpliedGraph { get; set; }

		public bool FullNodeMap { get; set; }

        // build a model & cache it
        GraphNodeCollection _nodes;
        protected GraphNodeCollection Nodes
        {
            get
            {
                if (_nodes == null)
                    _nodes = GraphNodeCollection.BuildModel(consolidation, EntityData);
                return _nodes;
            }
        }

		protected override void Hook(ref string html)
		{
			// full screen graphs
			html = html.Replace("<html lang=\"en\">", "<html style=\"height:100%; min-height: 100%;\">");
			html = html.Replace("<body>", "<body style=\"height: 100%; min-height: 100%;\">");
		}

		protected override string GenerateTitleInformation()
		{
			return "PingCastle AD Map " + DateTime.Now.ToString("yyyy-MM-dd") + " (" + Nodes.Count + " domains)";
		}

		protected override string GenerateHeaderInformation()
		{
			StringBuilder sb = new StringBuilder();
			sb.Append(@"<script>");
			sb.Append(TemplateManager.LoadVisJs());
			sb.Append(@"</script>");
			sb.Append(HealthCheckReportBase.GetStyleSheetTheme());
			sb.Append(@"<style type=""text/css"">

.modal
{
top: 50px;
}

.modal-header
{
background-color: #FA9C1A;
}
.modal-header h4 {color: #fff;}
.legend_criticalscore {
    background: #A856AA;
    border: #19231a;
    border-style: solid;
    border-width: 1px;
    padding: 5px;
}
.legend_superhighscore {
    background: #E75351;
    border: #19231a;
    border-style: solid;
    border-width: 1px;
    padding: 5px;
}
.legend_highscore {
    background: #FA9426;
    border: #19231a;
    border-style: solid;
    border-width: 1px;
    padding: 5px;
}
.legend_mediumscore {
    background: #FDC334;
    border: #19231a;
    border-style: solid;
    border-width: 1px;
    padding: 5px;
}

.legend_lowscore {
    background: #74C25C;
    border: #19231a;
    border-style: solid;
    border-width: 1px;
    padding: 5px;
}
.legend_unknown {
    background: #ffffff;
    border: #a352cc;
    border-style: solid;
    border-width: 1px;
    padding: 5px;
}
");
			sb.Append(TemplateManager.LoadVisCss());
			sb.Append(@"</style>");
			return sb.ToString();
		}

		protected override string GenerateBodyInformation()
		{
			StringBuilder sb = new StringBuilder();
			sb.Append(@"
<nav class=""navbar navbar-default navbar-fixed-top"" role=""navigation"">
    <div class=""container"">
        <div class=""navbar-header"">
            <button aria-controls=""navbar"" aria-expanded=""false"" data-target=""#navbar"" data-toggle=""collapse"" class=""navbar-toggle collapsed"" type=""button"">
                <i class=""fa fa-reorder""></i>
            </button>
            <a href=""https://www.pingcastle.com"" class=""navbar-brand"">
                <img src=""data:image/png;base64,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"" />
            </a>
        </div>
        <div class=""navbar-collapse collapse"" id=""navbar"">
            <ul class=""nav navbar-nav"">
                <li class=""active"">
                    <a aria-expanded=""false"" role=""button"" href=""#"">");
			sb.Append("Active Directory map");
			sb.Append(@"</a>
                </li>
				<li>
					<a aria-expanded=""false"" role=""button"">");
			sb.Append(DateTime.Now.ToString("yyyy-MM-dd"));
			sb.Append(@"</a>
				</li>
				<li>
					<a role=""button"" href=""#modalAbout"" data-toggle=""modal"">About</a>
				</li>
			</ul>
		</div>
	</div>
</nav>
<!-- Modal -->
<div class=""modal"" id=""modalAbout"" role=""dialog"">
    <div class=""modal-dialog"">
        <!-- Modal content-->
        <div class=""modal-content"">
            <div class=""modal-header"">
                <h4 class=""modal-title"">About</h4>
            </div>
            <div class=""modal-body"">
                <div class=""row"">
                     <div class=""col-lg-12"">
<p><strong>Generated by <a href=""https://www.pingcastle.com"">Ping Castle</a> all rights reserved</strong></p>
<p>Open source components:</p>
<ul>
<li><a href=""https://getbootstrap.com/"">Bootstrap</a> licensed under the <a href=""https://tldrlegal.com/license/mit-license"">MIT license</a></li>
<li><a href=""https://jquery.org"">JQuery</a> licensed under the <a href=""https://tldrlegal.com/license/mit-license"">MIT license</a></li>
<li><a href=""http://visjs.org/"">vis.js</a> licensed under the <a href=""https://tldrlegal.com/license/mit-license"">MIT license</a></li>
</ul>
                     </div>
                </div>
            </div>
            <div class=""modal-footer"">
                <button type=""button"" class=""btn btn-default"" data-dismiss=""modal"">Close</button>
            </div>
        </div>

    </div>
</div>
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
                    <div class=""progress-bar"" role=""progressbar"" aria-valuenow=""0"" aria-valuemin=""0"" aria-valuemax=""100"" style=""width: 0%"">
                        0%
                    </div>
                </div>
            </div>
        </div>

    </div>
</div>
<div id=""mynetwork"" class=""fill"" style=""height: 100%; min-height: 100%; border-width:1px;""></div>

<div id=""legend_carto"" style=""position: absolute;top: 55px;left: 0px;"">
    Legend: <br>
    <i class=""legend_criticalscore"">&nbsp;</i> score=100<br>
    <i class=""legend_superhighscore"">&nbsp;</i> score < 100<br>
    <i class=""legend_highscore"">&nbsp;</i> score < 70<br>
    <i class=""legend_mediumscore"">&nbsp;</i> score < 50<br>
    <i class=""legend_lowscore"">&nbsp;</i> score < 30<br>
    <i class=""legend_unknown"">&nbsp;</i> score unknown
</div>
");
			return sb.ToString();
		}

		protected override string GenerateFooterInformation()
		{
			StringBuilder sb = new StringBuilder();
			sb.Append(@"
<script>
    function getTooltipHtml(d) {
        var output = '<b>' + d.name + '</b>';
        if (d.FullEntityName != null) {
        output += '<br/>Entity: ' + d.FullEntityName;
    } else {
            if (d.BU != null) {
        output += '<br/>BU: ' + d.BU;
    }
            if (d.entity != null) {
        output += '<br/>Entity: ' + d.entity;
    }
        }
        if (d.forest != null) {
        output += '<br/>Forest: ' + d.forest;
    }
        if (d.score != null) {
			output += '<br/>Score: ' + d.score;
			output += '<ul>';
			output += '<li>StaleObjects: ' + d.staleObjectsScore;
			output += '<li>Privilegied Group: ' + d.privilegiedGroupScore;
			output += '<li>Trust: ' + d.trustScore;
			output += '<li>Anomaly: ' + d.anomalyScore;
			output += '</ul>';
        }
        return output;
    }

    var colors = {
                        'default': {background: '#CCCCCC', border: '#212121', highlight: {background: '#CCCCCC', border: '#212121' } },
        criticalscore: {background: '#A856AA', border: '#19231a', highlight: {background: '#A856AA', border: '#19231a' } },
        superhighscore: {background: '#E75351', border: '#19231a', highlight: {background: '#E75351', border: '#19231a' } },
        highscore: {background: '#FA9426', border: '#19231a', highlight: {background: '#FA9426', border: '#19231a' } },
        mediumscore: {background: '#FDC334', border: '#19231a', highlight: {background: '#FDC334', border: '#19231a' } },
        lowscore: {background: '#74C25C', border: '#19231a', highlight: {background: '#74C25C', border: '#19231a' } },
        ucriticalscore: {background: '#f3f3f3', border: '#B1B1B1', highlight: {background: '#A856AA', border: '#19231a' } },
        usuperhighscore: {background: '#f3f3f3', border: '#B1B1B1', highlight: {background: '#E75351', border: '#19231a' } },
        uhighscore: {background: '#f3f3f3', border: '#B1B1B1', highlight: {background: '#FA9426', border: '#19231a' } },
        umediumscore: {background: '#f3f3f3', border: '#B1B1B1', highlight: {background: '#FDC334', border: '#19231a' } },
        ulowscore: {background: '#f3f3f3', border: '#B1B1B1', highlight: {background: '#74C25C', border: '#19231a' } },
        unknown: {background: '#ffffff', border: '#a352cc', highlight: {background: '#ffffff', border: '#a352cc' } }
    };

function reshape(tree) {

    var nodes = [], edges = [], id = [0];
    function toNode(id, n, parentId, parentName, level, direction, nodes, edges) {
        id[0]++;
        var myId = id[0];
        node = {
            id: myId,
            name: n[""name""],
            shortname: n[""shortname""],
            FullEntityName: n[""FullEntityName""],
            PCEID: n[""PCEID""],
            level: level,
            score: n[""score""],
            staleObjectsScore: n[""staleObjectsScore""],
            privilegiedGroupScore: n[""privilegiedGroupScore""],
            trustScore: n[""trustScore""],
            anomalyScore: n[""anomalyScore""],
            BU: n[""BU""],
            Entity: n[""Entity""]
        };
        nodes.push(node);
        if (parentId != 0) {
            edge = {
                source: parentId,
                target: myId,
                rels: [parentName + ""->"" + n[""name""]]
            };
            edges.push(edge);
        }
        if ('children' in n) {
            for (var i = 0; i < n.children.length; i++) {
                var mydirection = direction;
                if (level == 0 && i > n.children.length / 2)
                    mydirection = -1;
                toNode(id, n.children[i], myId, n[""name""], level + mydirection, mydirection, nodes, edges);
            }
        }
    }
    toNode(id, tree, 0, """", 0, 1, nodes, edges);
    return { nodes: nodes, links: edges };
}

    function cartoSelectColor(n) {
        if (n['score'] <= 30) {
            return colors['lowscore'];
        }
        else if (n['score'] <= 50) {
            return colors['mediumscore'];
        }
        else if (n['score'] <= 70) {
            return colors['highscore'];
        }
        else if (n['score'] < 100) {
            return colors['superhighscore'];
        }
        else if (n['score'] == 100) {
            return colors['criticalscore'];
        }
        else
            return colors['unknown'];
    }

    function carto(data, hierachicalLayout) {
        var nodes = new vis.DataSet();
        var edges = new vis.DataSet();



        for (var i = 0; i < data.nodes.length; i++) {
            var n = data.nodes[i], node;

            node = {
                        // we use the count of the loop as an id if the id property setting is false
                        // this is in case the edges properties 'from' and 'to' are referencing
                        // the order of the node, not the real id.
                        id: n['id'],
                shortName: n['shortname'],
                value: 0 === n.dist ? 10 : 1,
                label: n['shortname'],
                title: getTooltipHtml(n),
                PCEID: n['PCEID'],
                level: n['level'],
                BU: n['BU'],
                Entity: n['Entity'],
                forest: n['forest'],
                color: cartoSelectColor(n)
            };
            nodes.add(node);
        }
        for (var j = 0; j < data.links.length; j++) {
            var l = data.links[j];
            var edge = {
                        from: l.source,
                to: l.target,
                data: {
                        rels: l.rels,
                    fromShortName: nodes.get(l.source).shortName,
                    fromBaseGroup: nodes.get(l.source).baseGroup,
                    toShortName: nodes.get(l.target).shortName,
                    toBaseGroup: nodes.get(l.target).baseGroup,
                    type: l.type
                },
                arrows: l.type === 'double' ? 'to, from' : 'to',
                title: l.rels.join('<br>'),
                color: {color: l.color, highlight: l.color, hover: l.color }
            };

            edges.add(edge);
        }

        // create a network
        var container = document.getElementById('mynetwork');
        var networkData = {
                            nodes: nodes,
            edges: edges
        };

        // create an array with nodes
        var options = {
                            //height: (window.innerHeight -130) + 'px',
                            //width: '100%',
                            height: '100%',
            autoResize: true,
            layout:
            {
                            improvedLayout: false
            },
            nodes: {
                            // you can use 'box', 'ellipse', 'circle', 'text' or 'database' here
                            // 'ellipse' is the default shape.
                            shape: 'ellipse',
                size: 20,
                font: {
                            //size: 15,
                            color: '#000000'
                    //face: 'arial' // maybe use a monospaced font?
                },
                borderWidth: 1,
                borderWidthSelected: 3,
                scaling: {
                            label: {
                            min: 15,
                        max: 25
                    }
                }
            },
            edges: {
                            width: 2,
                smooth: {
                            type: 'continuous'
                },
                hoverWidth: 2,
                selectionWidth: 2,
                arrows: {
                            to: {
                            enabled: true,
                        scaleFactor: 0.5
                    }, from: {
                            enabled: false,
                        scaleFactor: 0.5
                    }
                },
                color: {
                            //      inherit: 'from',
                            color: '#666666',
                    hover: '#333333',
                    highlight: '#000000'
                }
            },
            interaction: {
                            multiselect: true,
                hover: true,
                hideEdgesOnDrag: true
            }
        };
        if (hierachicalLayout) {
                            options.layout.hierarchical = { enabled: true, sortMethod: 'directed' };
                        } else {
                            options.physics = {
                                stabilization: {
                                    iterations: 2000 // try to stabilize the graph in 2000 times, after that show it anyway
                                },
                                barnesHut: {
                                    gravitationalConstant: -2000,
                                    centralGravity: 0.1,
                                    springLength: 95,
                                    springConstant: 0.04,
                                    damping: 0.09
                                },
                                enabled: true
                            };
                        }
        var network = new vis.Network(container, networkData, options);
        network.data = networkData;

        return network;
    }

var network;

var data = ");
			if (FullNodeMap)
			{
				sb.Append(GenerateJsonFileFull(migrationChecker));
			}
			else
			{
				sb.Append(GenerateJsonFileSimple(CenterDomainForSimpliedGraph));
				sb.Append(@"; data = reshape(data)");
			}
			sb.Append(@";

if (data.nodes.length > 0)
        $('#loadingModal').modal('show');
");
			sb.Append(@"
network = carto(data,");
			if (FullNodeMap)
				sb.Append("false");
			else
				sb.Append("true");
			sb.Append(@");
var progressBar = $('#loadingModal .progress-bar');

    network.on('stabilizationProgress', function (params) {
        var percentVal = 100 * params.iterations / params.total;
        progressBar.css('width', percentVal + '%').attr('aria-valuenow', percentVal + '%').text(percentVal + '%');
    });
    network.once('stabilizationIterationsDone', function () {
        var percentVal = 100;
        progressBar.css('width', percentVal + '%').attr('aria-valuenow', percentVal + '%').text(percentVal + '%');
        // really clean the dom element
        setTimeout(function () {
            $('#loadingModal').modal('hide')
        }, 100);
    });

</script>
");
			return sb.ToString();
		}


        #region json file
        private static bool NeedEscape(string src, int i)
        {
            char c = src[i];
            return c < 32 || c == '"' || c == '\\'
                // Broken lead surrogate
                || (c >= '\uD800' && c <= '\uDBFF' &&
                    (i == src.Length - 1 || src[i + 1] < '\uDC00' || src[i + 1] > '\uDFFF'))
                // Broken tail surrogate
                || (c >= '\uDC00' && c <= '\uDFFF' &&
                    (i == 0 || src[i - 1] < '\uD800' || src[i - 1] > '\uDBFF'))
                // To produce valid JavaScript
                || c == '\u2028' || c == '\u2029'
                // Escape "</" for <script> tags
                || (c == '/' && i > 0 && src[i - 1] == '<');
        }

        public static string EscapeJsonString(string src)
        {
            if (String.IsNullOrEmpty(src))
                return String.Empty;
            System.Text.StringBuilder sb = new System.Text.StringBuilder();

            int start = 0;
            for (int i = 0; i < src.Length; i++)
                if (NeedEscape(src, i))
                {
                    sb.Append(src, start, i - start);
                    switch (src[i])
                    {
                        case '\b': sb.Append("\\b"); break;
                        case '\f': sb.Append("\\f"); break;
                        case '\n': sb.Append("\\n"); break;
                        case '\r': sb.Append("\\r"); break;
                        case '\t': sb.Append("\\t"); break;
                        case '\"': sb.Append("\\\""); break;
                        case '\\': sb.Append("\\\\"); break;
                        case '/': sb.Append("\\/"); break;
                        default:
                            sb.Append("\\u");
                            sb.Append(((int)src[i]).ToString("x04"));
                            break;
                    }
                    start = i + 1;
                }
            sb.Append(src, start, src.Length - start);
            return sb.ToString();
        }

        public string GenerateJsonFileFull(MigrationChecker migrationChecker)
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
                sb.Append("      \"shortname\": \"" + EscapeJsonString(node.Domain.DomainName.Split('.')[0]) + "\"");
                if (node.IsPartOfARealForest())
                {
                    sb.Append("      ,\"forest\": \"" + EscapeJsonString(node.Forest.DomainName) + "\"");
                }
                var entity = node.Entity;
                if (entity != null)
                {
                    sb.Append(entity.GetJasonOutput());
                }
                HealthcheckData data = node.HealthCheckData;
                sb.Append("      ,\"name\": \"" + EscapeJsonString(node.Domain.DomainName) + "\"");
                if (data != null)
                {
                    sb.Append("      ,\"score\": " + data.GlobalScore);
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
            GenerateSimplifiedJason(sb,newCentralNode);
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
            sb.Append("  \"name\": \"" + EscapeJsonString(node.Domain.DomainName) + "\"\r\n");
            sb.Append("  ,\"shortname\": \"" + EscapeJsonString(node.Domain.DomainName.Split('.')[0]) + "\"\r\n");
            if (node.Forest != null && node.Forest != node.Domain)
            {
                sb.Append("      ,\"forest\": \"" + EscapeJsonString(node.Forest.DomainName) + "\"");
            }
            HealthcheckData data = node.HealthCheckData;
            if (data != null)
            {
                sb.Append("      ,\"score\": " + data.GlobalScore);
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

        #endregion json file
	}
}
