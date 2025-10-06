using PingCastle.Data;
using PingCastle.Healthcheck;
using PingCastle.misc;
using PingCastle.template;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Net;
using System.Reflection;

namespace PingCastle.Report
{
    public class ReportNetworkMap : ReportBase
    {
        private NetworkMapData data;

        public string GenerateReportFile(PingCastleReportCollection<HealthcheckData> report, ADHealthCheckingLicense license, string filename)
        {
            data = NetworkMapData.BuildFromConsolidation(report);
            return GenerateReportFile(filename);
        }

        public string GenerateRawContent(PingCastleReportCollection<HealthcheckData> report)
        {
            data = NetworkMapData.BuildFromConsolidation(report);
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


        protected class NetworkMapData
        {
            public List<NetworkMapDataView> Views { get; set; }
            public Dictionary<string, List<NetworkMapDataItem>> networkrange { get; set; }
            public List<NetworkMapDCItem> DomainControllers { get; set; }

            public static NetworkMapData BuildFromConsolidation(PingCastleReportCollection<HealthcheckData> reports)
            {
                var data = new NetworkMapData()
                {
                    Views = new List<NetworkMapDataView>() {
                        new NetworkMapDataView(){
                            framenetwork = Subnet.Parse("10.0.0.0/8"),
                            order = 1024,
                        },
                        new NetworkMapDataView()
                        {
                            framenetwork = Subnet.Parse("192.168.0.0/16"),
                            order = 256,
                        }
                    },
                };
                data.networkrange = new Dictionary<string, List<NetworkMapDataItem>>();
                data.DomainControllers = new List<NetworkMapDCItem>();
                var latestForestReports = new Dictionary<string, HealthcheckData>();

                Trace.WriteLine("NetworkMapData: 1");
                foreach (var report in reports)
                {
                    // select latest forest report to have the latest network information
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
                // store network information
                foreach (var report in latestForestReports.Values)
                {
                    var list = new List<NetworkMapDataItem>();
                    data.networkrange.Add(report.Forest.DomainSID, list);
                    foreach (var site in report.Sites)
                    {
                        foreach (var network in site.Networks)
                        {
                            // avoid bogus network definitions
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
                // tag the network
                foreach (var report in reports)
                {
                    IEnumerable<NetworkMapDataItem> networks = null;
                    if (report.Forest != null && 
                        !string.IsNullOrEmpty(report.Forest.DomainSID) && 
                        data.networkrange.ContainsKey(report.Forest.DomainSID))
                    {
                        networks = data.networkrange[report.Forest.DomainSID];
                    }
                    // collect DC info
                    foreach (var dc in report.DomainControllers)
                    {
                        if (dc.IP == null)
                            continue;
                        foreach (string ip in dc.IP)
                        {
                            IPAddress i;
                            if (!IPAddress.TryParse(ip, out i))
                            {
                                continue;
                            }
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
                                        else if (network.DomainFQDN == report.DomainFQDN)
                                        {

                                        }
                                        else
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

        }

        protected class NetworkMapDataView
        {
            public int order { get; set; }
            public Subnet framenetwork { get; set; }
            public bool HasData { get; set; }
            public int RecordCount { get; set; }
            public int ForestCount { get; set; }
        }

        protected class NetworkMapDataItem
        {
            public Subnet Network { get; set; }
            public string Source { get; set; }
            public string Name { get; set; }
            public string Description { get; set; }
            public string Location { get; set; }
            public string DomainFQDN { get; set; }
        }

        protected class NetworkMapDCItem
        {
            public string Source { get; set; }
            public string Name { get; set; }
            public IPAddress Ip { get; set; }

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
	<img class=""rounded map_view"" alt=""" + view.framenetwork + @""" src=""data:image/gif;base64,");
                    Add(Convert.ToBase64String(ms.ToArray()));
                    AddLine(@"""  view-id=""");
                    Add(id);
                    Add(@""" view-order=""256""/>");
                    AddLine(@"<i class=""map_view_tooltip"" data-bs-toggle=""tooltip"" data-bs-html=""true"" data-bs-placement=""right"" title=""No network found"" data-bs-animation=""false"" data-bs-trigger=""manual""></i>");
                    Add(@"
	<div class=""card-body"">
	<h5 class=""card-title"">" + view.framenetwork + @"</h5>
	<p class=""card-text"">The network ");
                    Add(view.framenetwork.ToString());
                    Add(" does match ");
                    Add(view.RecordCount);
                    Add(" networks. This information is coming from ");
                    Add(view.ForestCount);
                    Add(@" Active Directory forest(s).</p>
	<a href=""#"" class=""btn btn-primary btn-view"" view-id=""");
                    Add(id++);
                    Add(@""" view-order=""");
                    Add(view.order);
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
            const int order = 256;
            var uniqueForestSID = new List<string>();
            var subnets = new List<Subnet>();
            foreach (var key in data.networkrange.Keys)
                foreach (var subnet in data.networkrange[key])
                {
                    // keep only ipv4
                    if (subnet.Network.StartAddress.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                        continue;
                    // keep only networks that are visible
                    if (!view.framenetwork.MatchIp(subnet.Network.StartAddress) || !view.framenetwork.MatchIp(subnet.Network.EndAddress))
                        continue;
                    // avoiding filling all the space with larger networks
                    if (subnet.Network.MatchIp(view.framenetwork.StartAddress) && subnet.Network.MatchIp(view.framenetwork.EndAddress))
                        continue;
                    subnets.Add(subnet.Network);
                    if (!uniqueForestSID.Contains(key))
                        uniqueForestSID.Add(key);
                }
            if (subnets.Count == 0)
                return false;
            view.RecordCount = subnets.Count;
            view.ForestCount = uniqueForestSID.Count;
            using (Bitmap bitmap = new Bitmap(order, order, System.Drawing.Imaging.PixelFormat.Format32bppArgb))
            using (Graphics g = Graphics.FromImage(bitmap))
            using (SolidBrush drawBrush = new SolidBrush(Color.Black))
            using (SolidBrush dcBrush = new SolidBrush(Color.Red))
            using (StringFormat drawFormat1 = new StringFormat())
            {
                g.Clear(Color.GhostWhite);
                foreach (var s in subnets)
                {
                    ulong a = convertToN(s.StartAddress, view.framenetwork, order);
                    ulong b = convertToN(s.EndAddress, view.framenetwork, order);
                    for (ulong i = a; i <= b; i++)
                    {
                        int x = 0; int y = 0;
                        d2xy(order, (int)i, ref x, ref y);
                        g.FillRectangle(drawBrush, x, y, 1, 1);
                    }
                }
                foreach (var dc in data.DomainControllers)
                {
                    if (!view.framenetwork.MatchIp(dc.Ip))
                        continue;
                    ulong a = convertToN(dc.Ip, view.framenetwork, order);
                    int x = 0; int y = 0;
                    d2xy(order, (int)a, ref x, ref y);
                    g.FillRectangle(dcBrush, x, y, 2, 2);
                }
                bitmap.Save(stream, System.Drawing.Imaging.ImageFormat.Png);
            }
            return true;
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
                Add(view.order);
                AddLine(",");
                Add(@" ""name"": """);
                AddJsonEncoded(view.framenetwork.ToString());
                AddLine(@""",");
                Add(@" ""start"": ");
                Add(AdressToLong(view.framenetwork.StartAddress));
                AddLine(",");
                Add(@" ""end"": ");
                Add(AdressToLong(view.framenetwork.EndAddress));
                AddLine();
                AddLine("}");
            }
            AddLine("]");
            AddLine(@"</script>");
            AddLine(@"<script type=""application/json"" data-pingcastle-selector=""Network"">");
            AddLine(@"[");
            id = 0;
            foreach (var key in data.networkrange.Keys)
                foreach (var subnet in data.networkrange[key])
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
                    Add(AdressToLong(subnet.Network.StartAddress));
                    AddLine(",");
                    Add(@" ""end"": ");
                    Add(AdressToLong(subnet.Network.EndAddress));
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
                Add(AdressToLong(dc.Ip));
                AddLine("}");
            }
            AddLine("]");
            AddLine(@"</script>");
        }

        ulong convertToN(IPAddress point, Subnet range, int n)
        {
            var v1 = AdressToLong(range.StartAddress);
            var v = AdressToLong(range.EndAddress) - v1;
            return ((ulong)n * (ulong)n * (AdressToLong(point) - v1) / v);
        }

        ulong AdressToLong(IPAddress a)
        {
            var b = a.GetAddressBytes();
            return ((ulong)b[0] << 24) + ((ulong)b[1] << 16) + ((ulong)b[2] << 8) + (ulong)b[3];
        }

        //convert (x,y) to d
        int xy2d(int n, int x, int y)
        {
            int rx, ry, s, d = 0;
            for (s = n / 2; s > 0; s /= 2)
            {

                rx = Convert.ToInt32(((x & s) > 0));
                ry = Convert.ToInt32((y & s) > 0);
                d += s * s * ((3 * rx) ^ ry);
                rot(s, ref x, ref y, rx, ry);
            }
            return d;
        }

        //convert d to (x,y)
        void d2xy(int n, int d, ref int x, ref int y)
        {
            int rx, ry, s, t = d;
            x = y = 0;
            for (s = 1; s < n; s *= 2)
            {
                rx = 1 & (t / 2);
                ry = 1 & (t ^ rx);
                rot(s, ref x, ref y, rx, ry);
                x += s * rx;
                y += s * ry;
                t /= 4;
            }
        }

        //rotate/flip a quadrant appropriately
        void rot(int n, ref int x, ref int y, int rx, int ry)
        {
            if (ry == 0)
            {
                if (rx == 1)
                {
                    x = n - 1 - x;
                    y = n - 1 - y;
                }

                //Swap x and y
                int t = x;
                x = y;
                y = t;
            }
        }
    }
}
