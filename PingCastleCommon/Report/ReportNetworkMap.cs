using PingCastle.Data;
using PingCastle.Healthcheck;
using PingCastle.template;
using PingCastleCommon.Data;
using PingCastleCommon.Utility;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Reflection;

namespace PingCastle.Report
{
    public class ReportNetworkMap : ReportBase
    {
        private readonly IHilbertMapGenerator _hilbertGenerator;
        private NetworkMapData data;

        public ReportNetworkMap(IHilbertMapGenerator hilbertGenerator = null)
        {
            _hilbertGenerator = hilbertGenerator ?? new NullHilbertMapGenerator();
        }

        public string GenerateReportFile(PingCastleReportCollection<HealthcheckData> report, ADHealthCheckingLicense license, string filename)
        {
            data = BuildNetworkMapData(report);
            return GenerateReportFile(filename);
        }

        public string GenerateRawContent(PingCastleReportCollection<HealthcheckData> report)
        {
            data = BuildNetworkMapData(report);
            sb.Length = 0;
            GenerateContent();
            return sb.ToString();
        }

        protected override void GenerateFooterInformation()
        {
        }

        protected override void GenerateTitleInformation()
        {
            Add("PingCastle Network map - ");
            Add(DateTime.Now.ToString("yyyy-MM-dd"));
        }

        protected override void ReferenceJSAndCSS()
        {
            AddStyle(TemplateManager.LoadReportNetworkMapCss());
            AddScript(TemplateManager.LoadReportNetworkMapJs());
        }

        protected override void GenerateBodyInformation()
        {
            Version version = Assembly.GetExecutingAssembly().GetName().Version;
            string versionString = version.ToString(4);
#if DEBUG
            versionString += " Beta";
#endif
            GenerateNavigation("Network map", null);
            GenerateAbout();
            Add(@"
<div id=""wrapper"" class=""container well"">
	<noscript>
		<div class=""alert alert-warning"">
			<p>PingCastle reports work best with Javascript enabled.</p>
		</div>
	</noscript>
<div class=""row""><div class=""col-lg-12""><h1>Network map</h1>
			<h3>Date: " + DateTime.Now.ToString("yyyy-MM-dd") + @" - Engine version: " + versionString + @"</h3>
</div></div>
");
            GenerateContent();
            Add(@"
</div>
");
        }

        private static NetworkMapData BuildNetworkMapData(PingCastleReportCollection<HealthcheckData> reports)
        {
            var data = new NetworkMapData()
            {
                Views = new List<NetworkMapDataView>()
                {
                    new NetworkMapDataView()
                    {
                        FrameNetwork = Subnet.Parse("10.0.0.0/8"),
                        Order = 1024,
                    },
                    new NetworkMapDataView()
                    {
                        FrameNetwork = Subnet.Parse("192.168.0.0/16"),
                        Order = 256,
                    }
                },
            };
            data.NetworkRange = new Dictionary<string, List<NetworkMapDataItem>>();
            data.DomainControllers = new List<NetworkMapDCItem>();
            var latestForestReports = new Dictionary<string, HealthcheckData>();

            Trace.WriteLine("NetworkMapData: 1");
            foreach (var report in reports)
            {
                var version = new Version(report.EngineVersion.Split(' ')[0]);
                if (!(version.Major < 2 || (version.Major == 2 && version.Minor < 6)))
                {
                    if (report.Forest != null && !string.IsNullOrEmpty(report.Forest.DomainSID))
                    {
                        if (!latestForestReports.ContainsKey(report.Forest.DomainSID))
                        {
                            latestForestReports[report.Forest.DomainSID] = report;
                        }
                        else if (latestForestReports[report.Forest.DomainSID].GenerationDate < report.GenerationDate)
                        {
                            latestForestReports[report.Forest.DomainSID] = report;
                        }
                    }
                }
            }

            Trace.WriteLine("NetworkMapData: 2");
            foreach (var report in latestForestReports.Values)
            {
                var list = new List<NetworkMapDataItem>();
                data.NetworkRange.Add(report.Forest.DomainSID, list);
                foreach (var site in report.Sites)
                {
                    foreach (var network in site.Networks)
                    {
                        try
                        {
                            list.Add(new NetworkMapDataItem()
                            {
                                Network = Subnet.Parse(network),
                                Source = report.Forest.DomainName,
                                Description = site.Description,
                                Location = site.Location,
                                Name = site.SiteName,
                            });
                        }
                        catch (Exception)
                        { }
                    }
                }
            }

            Trace.WriteLine("NetworkMapData: 3");
            foreach (var report in reports)
            {
                IEnumerable<NetworkMapDataItem> networks = null;
                if (report.Forest != null &&
                    !string.IsNullOrEmpty(report.Forest.DomainSID) &&
                    data.NetworkRange.ContainsKey(report.Forest.DomainSID))
                {
                    networks = data.NetworkRange[report.Forest.DomainSID];
                }

                foreach (var dc in report.DomainControllers)
                {
                    if (dc.IP == null)
                        continue;
                    foreach (string ip in dc.IP)
                    {
                        if (!IPAddress.TryParse(ip, out var i))
                            continue;
                        if (i.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                            continue;
                        data.DomainControllers.Add(new NetworkMapDCItem()
                        {
                            Name = dc.DCName,
                            Source = report.DomainFQDN,
                            Ip = i,
                        });
                        if (networks != null)
                        {
                            foreach (var network in networks)
                            {
                                if (network.Network.MatchIp(i))
                                {
                                    if (string.IsNullOrEmpty(network.DomainFQDN))
                                    {
                                        network.DomainFQDN = report.DomainFQDN;
                                    }
                                    else if (network.DomainFQDN != report.DomainFQDN)
                                    {
                                        network.DomainFQDN = "_multiple_";
                                    }
                                }
                            }
                        }
                    }
                }
            }

            return data;
        }

        private void GenerateContent(string selectedTab = null)
        {
            Add(@"
<div class=""row"">
    <div class=""col-lg-12"">
		<ul class=""nav nav-tabs"" role=""tablist"">");
            GenerateTabHeader("Overview", selectedTab, true);
            GenerateTabHeader("Viewer", selectedTab);
            GenerateTabHeader("Network list", selectedTab);
            GenerateTabHeader("DC list", selectedTab);
            Add(@"
		</ul>
	</div>
	</div>
	<div class=""row"">
	<div class=""col-lg-12"">
		<div class=""tab-content"">");
            GenerateSectionFluid("Overview", GenerateOverview, selectedTab, true);
            GenerateSectionFluid("Viewer", GenerateMap, selectedTab);
            GenerateSectionFluid("Network list", GenerateNetworkList, selectedTab);
            GenerateSectionFluid("DC list", GenerateDCList, selectedTab);
            Add(@"
		</div>
	</div>
</div>");
        }

        private void GenerateOverview()
        {
            int id = 0;
            Add(@"
	<div class=""row"">
	<div class=""col-lg-12"">
<p>Networks are big and it can be difficult to have a visual representation of them. This report displays what is called a Hilbert map. Indeed, fractal functions are used to compress a 1D space (IP addresses of the networks), into 2D for a visual representation.
Each square represent a network. It can be used to detect non occupied space or networks which are overlapping.</p>
<p>Put your mouse over the map to display its legend.</p>
	<div class=""card-columns"">");
            foreach (var view in data.Views)
            {
                var ms = new MemoryStream();
                if (GenerateHilbertImage(ms, view))
                {
                    ms.Position = 0;

                    Add(@"
<div class=""card"">
	<img class=""rounded map_view"" alt=""" + view.FrameNetwork + @""" src=""data:image/gif;base64,");
                    Add(Convert.ToBase64String(ms.ToArray()));
                    AddLine(@"""  view-id=""");
                    Add(id);
                    Add(@""" view-order=""256""/>");
                    AddLine(@"<i class=""map_view_tooltip"" data-bs-toggle=""tooltip"" data-bs-html=""true"" data-bs-placement=""right"" title=""No network found"" data-bs-animation=""false"" data-bs-trigger=""manual""></i>");
                    Add(@"
	<div class=""card-body"">
	<h5 class=""card-title"">" + view.FrameNetwork + @"</h5>
	<p class=""card-text"">The network ");
                    Add(view.FrameNetwork.ToString());
                    Add(" does match ");
                    Add(view.RecordCount);
                    Add(" networks. This information is coming from ");
                    Add(view.ForestCount);
                    Add(@" Active Directory forest(s).</p>
	<a href=""#"" class=""btn btn-primary btn-view"" view-id=""");
                    Add(id++);
                    Add(@""" view-order=""");
                    Add(view.Order);
                    Add(@""">View</a>
	</div>
</div>");
                }
            }
            AddLine(@"</div></div></div>");
        }

        private void GenerateMap()
        {
            AddLine(@"
<!-- Modal -->
<div class=""modal"" id=""legenddialog"" role=""dialog"">
	<div class=""modal-dialog"">
		<!-- Modal content-->
		<div class=""modal-content"">
			<div class=""modal-header"">
				<h4 class=""modal-title"">Legend</h4>
				<button type=""button"" class=""btn-close btn-close-white"" data-bs-dismiss=""modal"" aria-label=""Close""></button>
			</div>
			<div class=""modal-body"">
				<div class=""row""><div class=""col-lg-1""><canvas id='dc_legend' width='20' height='20'></canvas>
				</div><div class=""col-lg-11""><p>Domain Controller</p>
				</div></div>
				<div class=""row""><div class=""col-lg-1""><canvas id='empty_legend' width='20' height='20'></canvas>
				</div><div class=""col-lg-11""><p>Network space without network discovered</p>
				</div></div>
				<div class=""row""><div class=""col-lg-1""><canvas id='filled_legend' width='20' height='20'></canvas>
				</div><div class=""col-lg-11""><p>Network discovered</p>
				</div></div>
				<div id='domain_legend'></div>
			</div>
		</div>
	</div>
</div>
<!-- Modal -->
<div class=""modal"" id=""filterdialog"" role=""dialog"">
	<div class=""modal-dialog"">
		<!-- Modal content-->
		<div class=""modal-content"">
			<div class=""modal-header"">
				<h4 class=""modal-title"">Filter source</h4>
				<button type=""button"" class=""btn-close btn-close-white"" data-bs-dismiss=""modal"" aria-label=""Close""></button>
            </div>
			<div class=""modal-body"">
				<div class=""panel-group"" id=""accordionFilter"">
				</div>
			</div>
		</div>
	</div>
</div>
<div class=""row""><div class=""col-lg-12"">
	<div class=""float-left"">
		<h2>Viewing network <span id='view-name'></span></h2>
		<p>Scale: 1 pixel is <span id='view-scale'></span> ip(s)</p>
	</div>
	<div class=""float-end""><div class=""btn-group"" role=""group"">
		<button type=""button"" class=""btn btn-default"" data-bs-toggle=""modal"" data-bs-target=""#legenddialog"">Show Legend</button>
		<button type=""button"" class=""btn btn-default"" data-bs-toggle=""modal"" data-bs-target=""#filterdialog"">Select Sources</button>
	</div></div>
</div></div>
<div class=""row""><div class=""col-lg-12"">
<form>
	<div class=""mb-3"">
		<label for=""InputIpMap"">Locate ip</label>
		<input type=""text"" required pattern=""^([0-9]{1,3}\.){3}[0-9]{1,3}$"" class=""form-control"" id=""InputIpMap"" aria-describedby=""ipHelp"" placeholder=""Enter ip address"">
		<div id=""validationfeedback"" class=""invalid-feedback""></div>
		<small id=""ipHelp"" class=""form-text text-muted"">Example: 10.0.1.0</small>
	</div>
</div></div>
<div class=""row""><div class=""col-lg-12"">
	<canvas  width='1024' height='1024' view-order='1024' view-id=""0"" class=""map_view"" id=""view"">
	</canvas>
	<i class=""map_view_tooltip"" data-bs-toggle=""tooltip"" data-bs-html=""true"" data-bs-placement=""right"" title=""No network found"" data-bs-animation=""false"" data-bs-trigger=""manual""></i>
</div></div>");
            GenerateJson();
        }

        private void GenerateNetworkList()
        {
            Add(@"
<div class=""row"">
<div class=""col-lg-12"">
<table class=""table table-striped table-bordered "" id=""network_list"" arial-label=""List of networks"">
	<thead>
	<tr> 
		<th>source</th>
		<th>name</th>
		<th>network</th>
		<th>description</th>
		<th>Use by</th>
	</tr>
	</thead>
</table>
</div>
</div>");
        }

        private void GenerateDCList()
        {
            Add(@"
<div class=""row"">
<div class=""col-lg-12"">
<table class=""table table-striped table-bordered "" id=""dc_list"" arial-label=""List of DC"">
	<thead>
	<tr> 
		<th>source</th>
		<th>name</th>
		<th>ip</th>
	</tr>
	</thead>
</table>
</div>
</div>");
        }

        private bool GenerateHilbertImage(Stream stream, NetworkMapDataView view)
        {
            return _hilbertGenerator.TryGenerateHilbertImage(stream, view, data);
        }

        void GenerateJson()
        {
            AddLine(@"<script type=""application/json"" data-pingcastle-selector=""Views"">");
            AddLine("[");
            int id = 0;
            foreach (var view in data.Views)
            {
                if (id != 0)
                    Add(",");
                AddLine("{");
                Add(@" ""id"": ");
                Add(id++);
                AddLine(",");
                Add(@" ""order"": ");
                Add(view.Order);
                AddLine(",");
                Add(@" ""name"": """);
                AddJsonEncoded(view.FrameNetwork.ToString());
                AddLine(@""",");
                Add(@" ""start"": ");
                Add(AddressToLong(view.FrameNetwork.StartAddress));
                AddLine(",");
                Add(@" ""end"": ");
                Add(AddressToLong(view.FrameNetwork.EndAddress));
                AddLine();
                AddLine("}");
            }
            AddLine("]");
            AddLine(@"</script>");
            AddLine(@"<script type=""application/json"" data-pingcastle-selector=""Network"">");
            AddLine(@"[");
            id = 0;
            foreach (var key in data.NetworkRange.Keys)
                foreach (var subnet in data.NetworkRange[key])
                {
                    if (id++ != 0)
                        Add(",");
                    AddLine("{");
                    Add(@" ""source"": """);
                    AddJsonEncoded(subnet.Source);
                    AddLine(@""",");
                    Add(@" ""name"": """);
                    AddJsonEncoded(subnet.Name);
                    AddLine(@""",");
                    Add(@" ""network"": """);
                    AddJsonEncoded(subnet.Network.ToString());
                    AddLine(@""",");
                    if (!String.IsNullOrEmpty(subnet.Description))
                    {
                        Add(@" ""description"": """);
                        AddJsonEncoded(subnet.Description);
                        AddLine(@""",");
                    }
                    if (!String.IsNullOrEmpty(subnet.Location))
                    {
                        Add(@" ""location"": """);
                        AddJsonEncoded(subnet.Location);
                        AddLine(@""",");
                    }
                    if (!String.IsNullOrEmpty(subnet.DomainFQDN))
                    {
                        Add(@" ""domainFQDN"": """);
                        AddJsonEncoded(subnet.DomainFQDN);
                        AddLine(@""",");
                    }
                    Add(@" ""start"": ");
                    Add(AddressToLong(subnet.Network.StartAddress));
                    AddLine(",");
                    Add(@" ""end"": ");
                    Add(AddressToLong(subnet.Network.EndAddress));
                    AddLine();
                    AddLine("}");
                }
            AddLine(@"]");
            AddLine(@"</script>");
            AddLine(@"<script type=""application/json"" data-pingcastle-selector=""DC"">");
            AddLine("[");
            id = 0;
            foreach (var dc in data.DomainControllers)
            {
                if (id != 0)
                    Add(",");
                AddLine("{");
                Add(@" ""id"": ");
                Add(id++);
                AddLine(",");
                Add(@" ""name"": """);
                AddJsonEncoded(dc.Name);
                AddLine(@""",");
                Add(@" ""source"": """);
                AddJsonEncoded(dc.Source);
                AddLine(@""",");
                Add(@" ""ip"": """);
                AddJsonEncoded(dc.Ip.ToString());
                AddLine(@""",");
                Add(@" ""iplong"": ");
                Add(AddressToLong(dc.Ip));
                AddLine("}");
            }
            AddLine("]");
            AddLine(@"</script>");
        }

        private ulong AddressToLong(IPAddress a)
        {
            var b = a.GetAddressBytes();
            return ((ulong)b[0] << 24) + ((ulong)b[1] << 16) + ((ulong)b[2] << 8) + (ulong)b[3];
        }
    }
}
