//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Data;
using PingCastle.template;
using System;
using System.Collections.Generic;
using System.Text;

namespace PingCastle.Healthcheck
{
	public class HealthCheckReportCompromiseGraph : HealthCheckReportBase
	{
		private CompromiseGraphData CompromiseGraphData;
		private readonly ADHealthCheckingLicense _license;

		public HealthCheckReportCompromiseGraph(CompromiseGraphData compromiseGraphData, ADHealthCheckingLicense license)
		{
			this.CompromiseGraphData = compromiseGraphData;
			_license = license;
			CompromiseGraphData.Data.Sort(
				(SingleCompromiseGraphData a, SingleCompromiseGraphData b)
				=>
				{
					return String.Compare(a.Description, b.Description);
				});
		}

		protected override void Hook(ref string html)
		{
			// full screen graphs
			html = html.Replace("<html lang=\"en\">", "<html style=\"height:100%; min-height: 100%;\">");
			html = html.Replace("<body>", "<body style=\"height: 100%; min-height: 100%;\">");
		}

		protected override string GenerateTitleInformation()
		{
			return "PingCastle Compromission Graphs - " + DateTime.Now.ToString("yyyy-MM-dd");
		}

		protected override string GenerateHeaderInformation()
		{
			StringBuilder sb = new StringBuilder();
			sb.Append(@"<script>");
			sb.Append(TemplateManager.LoadVisJs());
			sb.Append(@"</script>");
			sb.Append(HealthCheckReportBase.GetStyleSheetTheme());
			sb.Append(@"<style type=""text/css"">

.modal{top: 50px;}
.legend_user {background: #80b2ff; border: #0047b2;border-width: 1px;border-style: solid;font-family: monospace;padding:2px;}
.legend_fsp {background: #ffa366; border: #8f3900;border-width: 1px;border-style: solid;font-family: monospace;padding:2px;}
.legend_computer {background: #d65c33; border: #661a00;border-width: 1px;border-style: solid;font-family: monospace;padding:2px;}
.legend_group {background: #70db70; border: #196419;border-width: 1px;border-style: solid;font-family: monospace;padding:2px;}
.legend_ou {background: #cccccc; border: #333333;border-width: 1px;border-style: solid;font-family: monospace;padding:2px;}
.legend_gpo {background: #ad8533; border: #403100;border-width: 1px;border-style: solid;font-family: monospace;padding:2px;}
.legend_unknown {background: #ffffff; border: #a352cc;border-width: 1px;border-style: solid;font-family: monospace;padding:2px;}
.ticked{color:#4caf50}.unticked{color:#ff1744}
.info-mark {
    background-color: #fff;
    border-radius: 50%;
    border: 1px solid #58595b;
    color: #58595b;
    display: inline-block;
    font-size: 16px;
    height: 20px;
    text-align: center;
    vertical-align: middle;
    width: 20px;
    font-style: normal;
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
				
                <li class=""active nav-link"">
                    <a href=""#tab-main"" data-toggle=""tab"" id=""bs-tab-main"">");
			sb.Append("Active Directory Compromission Graph");
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
<p>This page has been inspired from the tools <a href=""https://github.com/ANSSI-FR/AD-control-paths"">Active Directory Control Paths</a>, <a href=""https://github.com/ANSSI-FR/OVALI"">OVALI</a> and <a href=""https://github.com/BloodHoundAD/BloodHound"">BloodHound</a>.</p>
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
<!--TAB PANEL -->
<div class=""panel-body"" style=""height: 100%; min-height: 100%;"">
    <div class=""tab-content"" style=""height: 100%; min-height: 100%;"">
<div class=""tab-pane in active"" id=""tab-main"">
<div id=""wrapper"" class=""container well"">
<noscript>
	<div class=""alert alert-alert"">
		<p><strong>This report requires javascript.</strong></p>
	</div>
</noscript>
<div class=""row""><div class=""col-lg-12""><h1>" + CompromiseGraphData.DomainFQDN + @" - Active Directory Compromission Graph</h1>
			<h3>Date: " + CompromiseGraphData.GenerationDate.ToString("yyyy-MM-dd") + @" - Engine version: " + CompromiseGraphData.EngineVersion + @"</h3>
</div></div>
<div class=""row"">
	<div class=""col-lg-12"">
			<div class=""alert alert-info"">
This report has been generated with the ");
			sb.Append(String.IsNullOrEmpty(_license.Edition) ? "Basic" : _license.Edition);
			sb.Append(@" Edition of PingCastle.");
			if (String.IsNullOrEmpty(_license.Edition))
			{
				sb.Append(@"
<br><strong>Being part of a commercial package is forbidden</strong> (selling the information contained in the report).<br>
If you are an auditor, you MUST purchase an Auditor license to share the development effort.
");
			}
			sb.Append(@"</div>
<p>The goal is to understand if, by doing some actions, a user account can gain more privileges than expected. For example, if a helpdesk user can reset a password account which is the owner of the login script of a domain admin, this user can become domain administrator.</p>
<p>Users, groups and other objects are connected through arrows which explain these links. The more objects there are, the more care should be used to check the highlighted path.</p>
<p>The paths made by PingCastle have known limitations compared to other tools to produce its quick analysis:</p>
<ul>
<li>PingCastle does not check for local server ACL like bloodhound does (file server, etc)</li>
<li>PingCastle does only perform its analysis on a single path direction. The report to understand what a simple user can do is not present.</li>
</ul>
<p><strong>This is a compromise between speed and accuracy.</strong></p>
<p>Select a graph to show its data then select Active Directory Compromission Graph to get back to this page again.</p>
</div></div>
<div class=""row"">
			<div class=""col-md-12 table-responsive"">
				<table class=""table table-striped table-bordered"">
	<thead>
	<tr><th>Group or user account <i class=""info-mark"" data-placement=""bottom"" data-toggle=""tooltip"" title="""" data-original-title=""The graph represents the objects which can take control of this group or user account."">?</i></th><th>On demand analysis <i class=""info-mark"" data-placement=""bottom"" data-toggle=""tooltip"" title="""" data-original-title=""In addition to the groups or users proposed by PingCastle, this checks indicates if the group or user has been manually selected"">?</i></th><th>Number of Account <i class=""info-mark"" data-placement=""bottom"" data-toggle=""tooltip"" title=""Indicates the number of local user accounts. Foreign users or groups are excluded."" data-original-title="""">?</i></th><th>Presence of unusual group <i class=""info-mark"" data-placement=""bottom"" data-toggle=""tooltip"" title="""" data-original-title=""This indicates if a group such as Everyone or Authenticated Users are part of the graph."">?</i></th></tr>
	</thead>
");
			for (int i = 0; i < CompromiseGraphData.Data.Count; i++)
			{
				var data = CompromiseGraphData.Data[i];
				sb.Append(@"<tr><td><a href=""#tab-graph-");
				sb.Append(i);
				sb.Append(@""" data-toggle=""tab"" id=""bs-tab-graph-");
				sb.Append(i);
				sb.Append(@""">");
				sb.Append(data.Description);
				sb.Append(@"</a></td><td>");
				if (data.OnDemandAnalysis)
				{
					sb.Append(@"✓");
				}
				sb.Append(@"</td><td>");
				int count = 0;
				foreach (var node in data.Nodes)
				{
					if (node.Distance == 0)
						continue;
					if (String.Equals(node.Type, "user", StringComparison.OrdinalIgnoreCase))
						count++;
				}
				sb.Append(count);
				sb.Append(@"</td><td>");
				if (data.UnusualGroup)
					sb.Append(@"<span class=""unticked"">YES</span>");
				else
					sb.Append(@"<span class=""ticked"">NO</span>");
				sb.Append(@"</td></tr>");
			}
			sb.Append(@"
		</table>
	</div>
</div>
</div>
</div>
");
			for (int i = 0; i < CompromiseGraphData.Data.Count; i++)
			{

				sb.Append(@"
                    <!--TAB Report -->
                    <div class=""tab-pane ");
				sb.Append(@""" id=""tab-graph-");
				sb.Append(i);
				sb.Append(@""" style=""height: 100%; min-height: 100%;"">
<div id=""mynetwork");
				sb.Append(i);
				sb.Append(@""" class=""fill"" style=""height: 100%; min-height: 100%; border-width:1px;""></div>

<div style=""position: absolute;top: 55px;left: 0px;"">
    Legend: <br>
    <i class=""legend_user"">u</i> user<br>
    <i class=""legend_fsp"">w</i> external user or group<br>
    <i class=""legend_computer"">m</i> computer<br>
    <i class=""legend_group"">g</i> group<br>
    <i class=""legend_ou"">o</i> OU<br>
    <i class=""legend_gpo"">x</i> GPO<br>
	<i class=""legend_unknown"">?</i> Other
</div>
</div>
");
			}
			sb.Append(@"
</div>
</div>");
			return sb.ToString();
		}

		protected override string GenerateFooterInformation()
		{
			StringBuilder sb = new StringBuilder();
			sb.Append(@"
<script>
    function getTooltipHtml(d) {
        var output = '<b>' + d.shortName + '</b>';
        output += '<br/>' + d.name;
		if (d.type != null)
			output += '<br/>type: ' + d.type;
        return output;
    }

    var colors = {
        'default': {background: ""#CCCCCC"", border: ""#212121"", highlight: {background: ""#CCCCCC"", border: ""#212121""}},
		user: {background: ""#80b2ff"", border: ""#0047b2"", highlight: {background: ""#80b2ff"", border: ""#0047b2""}},
		inetorgperson: {background: ""#80b2ff"", border: ""#0047b2"", highlight: {background: ""#80b2ff"", border: ""#0047b2""}},
		foreignsecurityprincipal: {background: ""#ffa366"", border: ""#8f3900"", highlight: {background: ""#ffa366"", border: ""#8f3900""}},
		computer: {background: ""#d65c33"", border: ""#661a00"", highlight: {background: ""#d65c33"", border: ""#661a00""}},
		group: {background: ""#70db70"", border: ""#196419"", highlight: {background: ""#70db70"", border: ""#196419""}},
		organizationalunit: {background: ""#cccccc"", border: ""#333333"", highlight: {background: ""#cccccc"", border: ""#333333""}},
		grouppolicycontainer: {background: ""#ad8533"", border: ""#403100"", highlight: {background: ""#ad8533"", border: ""#403100""}},
		unknown: {background: ""#ffffff"", border: ""#a352cc"", highlight: {background: ""#ffffff"", border: ""#a352cc""}},
    };
	var symbols = {
		'default': '-',
		user: 'u',
		inetorgperson: 'u',
		foreignsecurityprincipal: 'w',
		computer: 'm',
		group: 'g',
		organizationalunit: 'o',
		grouppolicycontainer: 'x',
		unknown: '?',
	};

    function carto(data, id) {
        var nodes = new vis.DataSet();
        var edges = new vis.DataSet();



        for (var i = 0; i < data.nodes.length; i++) {
            var n = data.nodes[i], node;

            node = {
                        // we use the count of the loop as an id if the id property setting is false
                        // this is in case the edges properties 'from' and 'to' are referencing
                        // the order of the node, not the real id.
                        id: n['id'],
                shortName: n['shortName'],
                value: 0 === n.dist ? 10 : 1,
                label: (n['type'] in symbols ? symbols[n['type']] : symbols['unknown']),
                title: getTooltipHtml(n),
                color: (n['type'] in colors ? colors[n['type']] : colors['unknown'])
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
                    /*fromShortName: nodes.get(l.source).shortName,
                    fromBaseGroup: nodes.get(l.source).baseGroup,
                    toShortName: nodes.get(l.target).shortName,
                    toBaseGroup: nodes.get(l.target).baseGroup,*/
                    type: l.type
                },
                arrows: l.type === 'double' ? 'to, from' : 'to',
                title: l.rels.join('<br>'),
                color: {color: l.color, highlight: l.color, hover: l.color }
            };

            edges.add(edge);
        }

        // create a network
        var container = document.getElementById('mynetwork' + id);
        var networkData = {
                            nodes: nodes,
            edges: edges
        };

        // create an array with nodes
        var options = {
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
                            color: '#000000',
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
                        
        var network = new vis.Network(container, networkData, options);
        network.data = networkData;

        return network;
    }

$('#bs-tab-main').on('shown.bs.tab', function () {

        history.pushState(null, null, $(this).attr('href'));
});

");
			for (int i = 0; i < CompromiseGraphData.Data.Count; i++)
			{
				sb.Append(@"
$('#bs-tab-graph-");
				sb.Append(i);
				sb.Append(@"').on('shown.bs.tab', function () {

        history.pushState(null, null, $(this).attr('href'));

	if(document.getElementById('mynetwork' + ");
				sb.Append(i);
				sb.Append(@").childNodes.length != 0)
		return;

	var network;

	var data = ");
				sb.Append(BuildJasonFromSingleCompromiseGraph(CompromiseGraphData.Data[i]));
				sb.Append(@";

	if (data.nodes.length > 0)
			$('#loadingModal').modal('show');

	network = carto(data,");
				sb.Append(i);
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
	});
");

			}
			sb.Append(@"
$("".nav-link"").click( function() {
            $("".nav-link"").removeClass(""active"");
        });
$(document).ready(function() {
	// navigate to a tab when the history changes
	window.addEventListener(""popstate"", function(e) {

		var hash = location.hash;
		if (hash.length > 0)
			hash = hash.substring(1);
		else
			hash = ""tab-main"";
		$('#bs-' + hash).trigger(""click"");
	});
});
$(function () {
	$('[data-toggle=""tooltip""]').tooltip();
});
</script>
");
			return sb.ToString();
		}


		string BuildJasonFromSingleCompromiseGraph(SingleCompromiseGraphData data)
		{
			StringBuilder output = new StringBuilder();
			Dictionary<int, int> idconversiontable = new Dictionary<int, int>();
			output.Append("{");
			// START OF NODES

			output.Append("  \"nodes\": [");
			// it is important to put the root node as the first node for correct display
			for (int i = 0; i < data.Nodes.Count; i++)
			{
				var node = data.Nodes[i];
				if (i != 0)
					output.Append("    },");
				output.Append("    {");
				output.Append("      \"id\": " + node.Id + ",");
				output.Append("      \"name\": \"" + HealthCheckReportMapBuilder.EscapeJsonString(node.Name) + "\",");
				output.Append("      \"type\": \"" + node.Type + "\",");
				output.Append("      \"shortName\": \"" + HealthCheckReportMapBuilder.EscapeJsonString(node.ShortName) + "\",");
				if (node.Distance == 0)
					output.Append("      \"dist\": null");
				else
					output.Append("      \"dist\": \"" + node.Distance + "\"");
			}
			output.Append("    }");
			output.Append("  ],");
			// END OF NODES

			// START LINKS
			output.Append("  \"links\": [");
			// avoid a final ","
			for (int i = 0; i < data.Links.Count; i++)
			{
				var relation = data.Links[i];
				if (i != 0)
					output.Append("    },");

				output.Append("    {");
				output.Append("      \"source\": " + relation.Source + ",");
				output.Append("      \"target\": " + relation.Target + ",");
				output.Append("      \"rels\": [");
				for (int j = 0; j < relation.Hints.Count; j++)
				{
					output.Append("         \"" + data.Links[i].Hints[j] + "\"" + (j == relation.Hints.Count - 1 ? String.Empty : ","));
				}

				output.Append("       ]");
			}
			if (data.Links.Count > 0)
			{
				output.Append("    }");
			}
			output.Append("  ]");
			// END OF LINKS
			output.Append("}");
			return output.ToString();
		}

	}
}
