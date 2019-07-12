//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.Reflection;
using System.Text;
using PingCastle.Data;
using PingCastle.Healthcheck;
using PingCastle.Rules;
using PingCastle.template;

namespace PingCastle.Report
{
    public class ReportHealthCheckConsolidation : ReportRiskControls<HealthcheckData>
    {
        private PingCastleReportCollection<HealthcheckData> Report;

		public string GenerateReportFile(PingCastleReportCollection<HealthcheckData> report, ADHealthCheckingLicense license, string filename)
		{
			Report = report;
			return GenerateReportFile(filename);
		}

		public string GenerateRawContent(PingCastleReportCollection<HealthcheckData> report, string selectedTab = null)
		{
			Report = report;
			sb.Length = 0;
			GenerateContent(selectedTab);
			return sb.ToString();
		}

        protected override void GenerateFooterInformation()
        {
			AddBeginScript();
			AddLine(TemplateManager.LoadJqueryDatatableJs());
			AddLine(TemplateManager.LoadDatatableJs());
			AddLine(@"
$('table').not('.model_table').DataTable(
    {
        'paging': false,
        'searching': false
    }
);
			</script>");
        }

        protected override void GenerateTitleInformation()
        {
			Add("PingCastle Consolidation report - ");
			Add(DateTime.Now.ToString("yyyy-MM-dd"));
        }

        protected override void GenerateHeaderInformation()
        {
			AddBeginStyle();
			AddLine(TemplateManager.LoadDatatableCss());
			AddLine(GetStyleSheetTheme());
			AddLine(GetStyleSheet());
			AddLine(@"</style>"); 
        }

        public static string GetStyleSheet()
        {
            return @"
.panel.with-nav-tabs .panel-heading{
    padding: 5px 5px 0 5px;
}
.panel.with-nav-tabs .nav-tabs{
	border-bottom: none;
}
.panel.with-nav-tabs .nav-justified{
	margin-bottom: -1px;
}
/********************************************************************/
/*** PANEL DEFAULT ***/
.with-nav-tabs.panel-default .nav-tabs > li > a,
.with-nav-tabs.panel-default .nav-tabs > li > a:hover,
.with-nav-tabs.panel-default .nav-tabs > li > a:focus {
    color: #777;
}
.with-nav-tabs.panel-default .nav-tabs > .open > a,
.with-nav-tabs.panel-default .nav-tabs > .open > a:hover,
.with-nav-tabs.panel-default .nav-tabs > .open > a:focus,
.with-nav-tabs.panel-default .nav-tabs > li > a:hover,
.with-nav-tabs.panel-default .nav-tabs > li > a:focus {
    color: #777;
	background-color: #ddd;
	border-color: transparent;
}
.with-nav-tabs.panel-default .nav-tabs > li.active > a,
.with-nav-tabs.panel-default .nav-tabs > li.active > a:hover,
.with-nav-tabs.panel-default .nav-tabs > li.active > a:focus {
	color: #555;
	background-color: #fff;
	border-color: #ddd;
	border-bottom-color: transparent;
}
.with-nav-tabs.panel-default .nav-tabs > li.dropdown .dropdown-menu {
    background-color: #f5f5f5;
    border-color: #ddd;
}
.with-nav-tabs.panel-default .nav-tabs > li.dropdown .dropdown-menu > li > a {
    color: #777;   
}
.with-nav-tabs.panel-default .nav-tabs > li.dropdown .dropdown-menu > li > a:hover,
.with-nav-tabs.panel-default .nav-tabs > li.dropdown .dropdown-menu > li > a:focus {
    background-color: #ddd;
}
.with-nav-tabs.panel-default .nav-tabs > li.dropdown .dropdown-menu > .active > a,
.with-nav-tabs.panel-default .nav-tabs > li.dropdown .dropdown-menu > .active > a:hover,
.with-nav-tabs.panel-default .nav-tabs > li.dropdown .dropdown-menu > .active > a:focus {
    color: #fff;
    background-color: #555;
}

.model_table {

}
.model_table th {
	padding: 5px;
}
.model_cell {
	border: 2px solid black;
	padding: 5px;
}
.model_empty_cell {
}
div_model {
	
}
.model_cell.model_good {
	//background-color: #83e043;
	//color: #FFFFFF;
}
.model_cell.model_toimprove
{
	background-color: #ffd800;
	//color: #FFFFFF;
}
.model_cell.model_info {
	background-color: #00AAFF;
color: #FFFFFF;
}
.model_cell.model_warning {
	background-color: #ff6a00;
color: #FFFFFF;
}
.model_cell.model_danger {
	background-color: #f12828;
color: #FFFFFF;
}
.model_cell  .popover{
    max-width: 100%;
}
.model_cell .popover-content {
	color: #000000;
}
.model_cell .popover-title {
	color: #000000;
}

/* gauge */
.arc
{
}
.chart-first
{
	fill: #83e043;
}
.chart-second
{
	fill: #ffd800;
}
.chart-third
{
	fill: #ff6a00;
}
.chart-quart
{
	fill: #f12828;
}

.needle, .needle-center
{
	fill: #000000;
}
.text {
	color: ""#112864"";
}
svg {
	font: 10px sans-serif;
}
";
        }

		protected override void Hook(StringBuilder sbHtml)
        {
			sbHtml.Replace("<body>", @"<body data-spy=""scroll"" data-target="".navbar"" data-offset=""50"">");
        }

        protected override void GenerateBodyInformation()
        {
            Version version = Assembly.GetExecutingAssembly().GetName().Version;
            string versionString = version.ToString(4);
#if DEBUG
            versionString += " Beta";
#endif
			GenerateNavigation("Consolidation", null, DateTime.Now);
			GenerateAbout(@"<p><strong>Generated by <a href=""https://www.pingcastle.com"">Ping Castle</a> all rights reserved</strong></p>
<p>Open source components:</p>
<ul>
<li><a href=""https://getbootstrap.com/"">Bootstrap</a> licensed under the <a href=""https://tldrlegal.com/license/mit-license"">MIT license</a></li>
<li><a href=""https://datatables.net/"">DataTables</a> licensed under the <a href=""https://tldrlegal.com/license/mit-license"">MIT license</a></li>
<li><a href=""https://popper.js.org/"">Popper.js</a> licensed under the <a href=""https://tldrlegal.com/license/mit-license"">MIT license</a></li>
<li><a href=""https://jquery.org"">JQuery</a> licensed under the <a href=""https://tldrlegal.com/license/mit-license"">MIT license</a></li>
</ul>");
			Add(@"
<div id=""wrapper"" class=""container-fluid well"">
	<noscript>
		<div class=""alert alert-warning"">
			<p>PingCastle reports work best with Javascript enabled.</p>
		</div>
	</noscript>
<div class=""row""><div class=""col-lg-12""><h1>Consolidation</h1>
			<h3>Date: " + DateTime.Now.ToString("yyyy-MM-dd") + @" - Engine version: " + versionString + @"</h3>
</div></div>
");
			GenerateContent();
			Add(@"
</div>
");
        }

        void GenerateContent(string selectedTab = null)
        {
            Add(@"
<div class=""row"">
    <div class=""col-lg-12"">
		<ul class=""nav nav-tabs"" role=""tablist"">");
            GenerateTabHeader("Active Directory Indicators", selectedTab, true);
            GenerateTabHeader("Rules Matched", selectedTab);
            GenerateTabHeader("Domain Information", selectedTab);
            GenerateTabHeader("User Information", selectedTab);
            GenerateTabHeader("Computer Information", selectedTab);
            GenerateTabHeader("Admin Groups", selectedTab);
            GenerateTabHeader("Trusts", selectedTab);
            GenerateTabHeader("Anomalies", selectedTab);
            GenerateTabHeader("Password Policies", selectedTab);
            GenerateTabHeader("GPO", selectedTab);
            Add(@"
        </ul>
    </div>
</div>
<div class=""row"">
    <div class=""col-lg-12"">
		<div class=""tab-content"">");

            GenerateSectionFluid("Active Directory Indicators", GenerateIndicators, selectedTab, true);
            GenerateSectionFluid("Rules Matched", GenerateRulesMatched, selectedTab);
            GenerateSectionFluid("Domain Information", GenerateDomainInformation, selectedTab);
            GenerateSectionFluid("User Information", GenerateUserInformation, selectedTab);
            GenerateSectionFluid("Computer Information", GenerateComputerInformation, selectedTab);
            GenerateSectionFluid("Admin Groups", GenerateAdminGroupsInformation, selectedTab);
            GenerateSectionFluid("Trusts", GenerateTrustInformation, selectedTab);
            GenerateSectionFluid("Anomalies", GenerateAnomalyDetail, selectedTab);
            GenerateSectionFluid("Password Policies", GeneratePasswordPoliciesDetail, selectedTab);
            GenerateSectionFluid("GPO", GenerateGPODetail, selectedTab);

            Add(@"
		</div>
	</div>
</div>");
        }

        private void GenerateRulesMatched()
        {
            Add(@"
		<div class=""row"">
			<div class=""col-md-12 table-responsive"">
				<table class=""table table-striped table-bordered"">
					<thead><tr> 
						<th>Domain</th>
						<th>Category</th>
						<th>Rule</th>
						<th>Score</th>
						<th>Description</th>
						<th>Rationale</th>
						</tr>
					</thead>
					<tbody>
");
            foreach (HealthcheckData data in Report)
            {
                foreach (HealthcheckRiskRule rule in data.RiskRules)
                {
                    Add(@"
						<tr>
							<td class='text'>" + PrintDomain(data.Domain) + @"</td>
							<td class='text'>" + rule.Category + @"</td>
							<td class='text'>" + rule.RiskId + @"</td>
							<td class='num'>" + rule.Points + @"</td>
							<td class='text'>" + RuleSet<HealthcheckData>.GetRuleDescription(rule.RiskId) + @"</td>
							<td class='text'>" + rule.Rationale + @"</td>
						</tr>");
                }
            }
            Add(@"
					</tbody>
				</table>
			</div>
		</div>");
        }

        #region indicators

        private void GenerateIndicators()
        {
            int globalScore = 0, minscore = 0, maxscore = 0, medianscore = 0;
            int sumScore = 0, num = 0;
            List<int> AllScores = new List<int>();
            foreach (var data in Report)
            {
                num++;
                sumScore += data.GlobalScore;
                AllScores.Add(data.GlobalScore);
            }
            if (num > 0)
            {
                AllScores.Sort();

                globalScore = sumScore / num;
                minscore = AllScores[0];
                maxscore = AllScores[AllScores.Count - 1];
                if (AllScores.Count % 2 == 0)
                {
                    var firstValue = AllScores[(AllScores.Count / 2) - 1];
                    var secondValue = AllScores[(AllScores.Count / 2)];
                    medianscore = (firstValue + secondValue) / 2;
                }
                if (AllScores.Count % 2 == 1)
                {
                    medianscore = AllScores[(AllScores.Count / 2)];
                }
            }
            Add(@"
        <div class=""row""><div class=""col-lg-12"">
			<a data-toggle=""collapse"" data-target=""#indicators"">
				<h2>Indicators</h2>
			</a>
		</div></div>
        <div class=""row"">
			<div class=""col-md-4"">
				<div class=""chart-gauge"">");
            GenerateGauge(globalScore);
            Add(@"</div>
			</div>
			<div class=""col-md-8"">
					<p class=""lead"">Average Risk Level: " + globalScore + @" / 100</p>
                    <p>Best Risk Level: " + minscore + @" / 100</p>
                    <p>Worst Risk Level: " + maxscore + @" / 100</p>
                    <p>Median Risk Level: " + medianscore + @" / 100</p>
			</div>
		</div>
");
			var rules = new List<HealthcheckRiskRule>();
			foreach (HealthcheckData data in Report)
			{
				rules.AddRange(data.RiskRules);
			}
			GenerateRiskModelPanel(rules, Report.Count);
            GenerateIndicatorsTable();
        }

        private void GenerateIndicatorsTable()
        {
            Add(@"
		<div class=""row""><div class=""col-lg-12"">
			<a data-toggle=""collapse"" data-target=""#scoreDetail"">
				<h2>Score detail</h2>
			</a>
		</div></div>
        <div class=""row"">
			<div class=""col-md-12 table-responsive"">
				<table class=""table table-striped table-bordered"">
				<thead><tr> 
					<th>Domain</th>
					<th>Domain Risk Level</th>
					<th>Stale objects</th>
					<th>Privileged accounts</th>
					<th>Trusts</th>
					<th>Anomalies</th>
					<th>Generated</th>
					</tr>
				</thead>
				<tbody>
");
            foreach (HealthcheckData data in Report)
            {
                Add(@"
					<tr>
						<td class='text'>" + PrintDomain(data.Domain) + @"</td>
						<td class='num'>" + data.GlobalScore + @"</td>
						<td class='num'>" + data.StaleObjectsScore + @"</td>
						<td class='num'>" + data.PrivilegiedGroupScore + @"</td>
						<td class='num'>" + data.TrustScore + @"</td>
						<td class='num'>" + data.AnomalyScore + @"</td>
						<td class='text'>" + data.GenerationDate.ToString("u") + @"</td>
					</tr>");
            }
            Add(@"
				</tbody>
				</table>
			</div>
		</div>
");
        }
        #endregion indicators

        #region domain information
        private void GenerateDomainInformation()
        {
            Add(@"
		<div class=""row"">
			<div class=""col-md-12 table-responsive"">
				<table class=""table table-striped table-bordered"">
					<thead><tr> 
						<th>Domain</th>
						<th>Netbios Name</th>
						<th>Domain Functional Level</th>
						<th>Forest Functional Level</th>
						<th>Creation date</th>
						<th>Nb DC</th>
						<th>Engine</th>
						<th>Level</th>
						<th>Schema version</th>
						</tr>
					</thead>
					<tbody>
");
            foreach (HealthcheckData data in Report)
            {
                Add(@"
						<tr>
							<td class='text'>");
				Add(PrintDomain(data.Domain));
				Add(@"</td>
							<td class='text'>");
				AddEncoded(data.NetBIOSName);
				Add(@"</td>
							<td class='text'>");
				Add(ReportHelper.DecodeDomainFunctionalLevel(data.DomainFunctionalLevel));
				Add(@"</td>
							<td class='text'>");
				Add(ReportHelper.DecodeForestFunctionalLevel(data.ForestFunctionalLevel));
				Add(@"</td>
							<td class='text'>");
				Add(data.DomainCreation.ToString("u"));
				Add(@"</td>
							<td class='num'>");
				Add(data.NumberOfDC);
				Add(@"</td>
							<td class='text'>");
				Add(data.EngineVersion);
				Add(@"</td>
							<td class='text'>");
				Add(data.Level.ToString());
				Add(@"</td>
							<td class='text'>");
				Add(ReportHelper.GetSchemaVersion(data.SchemaVersion));
				Add(@"</td>
						</tr>");
            }
            Add(@"
					</tbody>
					<tfoot>
						<tr>
							<td class='text'><b>Total</b></td>
							<td class='num'>" + Report.Count + @"</td>
						</tr>
					</tfoot>
				</table>
			</div>
		</div>
");
        }
        #endregion domain information

        #region user
        private void GenerateUserInformation()
        {
            Add(@"
		<div class=""row"">
			<div class=""col-md-12 table-responsive"">
				<table class=""table table-striped table-bordered"">
				<thead><tr>
					<th>Domain</th>
					<th>Nb User Accounts</th>
					<th>Nb Enabled</th>
					<th>Nb Disabled</th>
					<th>Nb Active</th>
					<th>Nb Inactive</th>
					<th>Nb Locked</th>
					<th>Nb pwd never Expire</th>
					<th>Nb SidHistory</th>
					<th>Nb Bad PrimaryGroup</th>
					<th>Nb Password not Req.</th>
					<th>Nb Des enabled.</th>
					<th>Nb Trusted delegation</th>
					<th>Nb Reversible password</th>
					</tr>
				</thead>
				<tbody>
");
            HealthcheckAccountData total = new HealthcheckAccountData();
            foreach (HealthcheckData data in Report)
            {
                total.Add(data.UserAccountData);
                Add(@"
					<tr>
						<td class='text'>" + PrintDomain(data.Domain) + @"</td>
						<td class='num'>" + data.UserAccountData.Number + @"</td>
						<td class='num'>" + data.UserAccountData.NumberEnabled + @"</td>
						<td class='num'>" + data.UserAccountData.NumberDisabled + @"</td>
						<td class='num'>" + data.UserAccountData.NumberActive + @"</td>
						<td class='num'>" + data.UserAccountData.NumberInactive + @"</td>
						<td class='num'>" + data.UserAccountData.NumberLocked + @"</td>
						<td class='num'>" + data.UserAccountData.NumberPwdNeverExpires + @"</td>
						<td class='num'>" + data.UserAccountData.NumberSidHistory + @"</td>
						<td class='num'>" + data.UserAccountData.NumberBadPrimaryGroup + @"</td>
						<td class='num'>" + data.UserAccountData.NumberPwdNotRequired + @"</td>
						<td class='num'>" + data.UserAccountData.NumberDesEnabled + @"</td>
						<td class='num'>" + data.UserAccountData.NumberTrustedToAuthenticateForDelegation + @"</td>
						<td class='num'>" + data.UserAccountData.NumberReversibleEncryption + @"</td>
					</tr>");
            }
            Add(@"
				</tbody>
				<tfoot>
					<tr>
						<td class='text'><b>Total</b></td>
						<td class='num'><b>" + total.Number + @"</b></td>
						<td class='num'><b>" + total.NumberEnabled + @"</b></td>
						<td class='num'><b>" + total.NumberDisabled + @"</b></td>
						<td class='num'><b>" + total.NumberActive + @"</b></td>
						<td class='num'><b>" + total.NumberInactive + @"</b></td>
						<td class='num'><b>" + total.NumberLocked + @"</b></td>
						<td class='num'><b>" + total.NumberPwdNeverExpires + @"</b></td>
						<td class='num'><b>" + total.NumberSidHistory + @"</b></td>
						<td class='num'><b>" + total.NumberBadPrimaryGroup + @"</b></td>
						<td class='num'><b>" + total.NumberPwdNotRequired + @"</b></td>
						<td class='num'><b>" + total.NumberDesEnabled + @"</b></td>
						<td class='num'><b>" + total.NumberTrustedToAuthenticateForDelegation + @"</b></td>
						<td class='num'><b>" + total.NumberReversibleEncryption + @"</b></td>
					</tr>
				</tfoot>
				</table>
			</div>
		</div>
");
        }
        #endregion user

        #region computer
        private void GenerateComputerInformation()
        {
            Add(@"
		<div class=""row"">
			<div class=""col-md-12 table-responsive"">
				<table class=""table table-striped table-bordered"">
				<thead><tr> 
					<th>Domain</th>
					<th>Nb Computer Accounts</th>
					<th>Nb Enabled</th>
					<th>Nb Disabled</th>
					<th>Nb Active</th>
					<th>Nb Inactive</th>
					<th>Nb SidHistory</th>
					<th>Nb Bad PrimaryGroup</th>
					<th>Nb Trusted delegation</th>
					<th>Nb Reversible password</th>
					</tr>
				</thead>
				<tbody>
");
            HealthcheckAccountData total = new HealthcheckAccountData();
            foreach (HealthcheckData data in Report)
            {
                total.Add(data.ComputerAccountData);
                Add(@"
					<tr>
						<td class='text'>" + PrintDomain(data.Domain) + @"</td>
						<td class='num'>" + data.ComputerAccountData.Number + @"</td>
						<td class='num'>" + data.ComputerAccountData.NumberEnabled + @"</td>
						<td class='num'>" + data.ComputerAccountData.NumberDisabled + @"</td>
						<td class='num'>" + data.ComputerAccountData.NumberActive + @"</td>
						<td class='num'>" + data.ComputerAccountData.NumberInactive + @"</td>
						<td class='num'>" + data.ComputerAccountData.NumberSidHistory + @"</td>
						<td class='num'>" + data.ComputerAccountData.NumberBadPrimaryGroup + @"</td>
						<td class='num'>" + data.ComputerAccountData.NumberTrustedToAuthenticateForDelegation + @"</td>
						<td class='num'>" + data.ComputerAccountData.NumberReversibleEncryption + @"</td>
					</tr>");
            }
            Add(@"
				</tbody>
				<tfoot>
				<tr>
				<td class='text'><b>Total</b></td>
				<td class='num'><b>" + total.Number + @"</b></td>
				<td class='num'><b>" + total.NumberEnabled + @"</b></td>
				<td class='num'><b>" + total.NumberDisabled + @"</b></td>
				<td class='num'><b>" + total.NumberActive + @"</b></td>
				<td class='num'><b>" + total.NumberInactive + @"</b></td>
				<td class='num'><b>" + total.NumberSidHistory + @"</b></td>
				<td class='num'><b>" + total.NumberBadPrimaryGroup + @"</b></td>
				<td class='num'><b>" + total.NumberTrustedToAuthenticateForDelegation + @"</b></td>
				<td class='num'><b>" + total.NumberReversibleEncryption + @"</b></td>
				</tr>
				</tfoot>
				</table>
			</div>
		</div>
");
            GenerateConsolidatedOperatingSystemList();
        }

        private string GenerateConsolidatedOperatingSystemList()
        {
            string output = null;
            List<string> AllOS = new List<string>();
            Dictionary<string, int> SpecificOK = new Dictionary<string, int>();
            foreach (HealthcheckData data in Report)
            {
                if (data.OperatingSystem != null)
                {
                    foreach (HealthcheckOSData os in data.OperatingSystem)
                    {
                        // keep only the "good" operating system (OsToInt>0)
                        if (OSToInt(os.OperatingSystem) > 0)
                        {
                            if (!AllOS.Contains(os.OperatingSystem))
                                AllOS.Add(os.OperatingSystem);
                        }
                        else
                        {
                            // consolidate all other OS
                            if (!SpecificOK.ContainsKey(os.OperatingSystem))
                                SpecificOK[os.OperatingSystem] = os.NumberOfOccurence;
                            else
                                SpecificOK[os.OperatingSystem] += os.NumberOfOccurence;
                        }
                    }
                }
            }
            AllOS.Sort(OrderOS);
            Add(@"
		<div class=""row"">
			<div class=""col-md-12 table-responsive"">
				<table class=""table table-striped table-bordered"">
					<thead><tr> 
						<th>Domain</th>
");
            foreach (string os in AllOS)
            {
                Add("<th>");
				AddEncoded(os);
				Add("</th>\r\n");
            }
            Add(@"
						</tr>
					</thead>
					<tbody>
");
            // maybe not the most perfomant algorithm (n^4) but there is only a few domains to consolidate
            foreach (HealthcheckData data in Report)
            {
                Add(@"<tr>
<td class='text'>" + PrintDomain(data.Domain) + @"</td>
");
                foreach (string os in AllOS)
                {
                    int numberOfOccurence = -1;
                    if (data.OperatingSystem != null)
                    {
                        foreach (var OS in data.OperatingSystem)
                        {
                            if (OS.OperatingSystem == os)
                            {
                                numberOfOccurence = OS.NumberOfOccurence;
                                break;
                            }
                        }
                    }
                    Add("<td class='num'>" + (numberOfOccurence >= 0 ? numberOfOccurence.ToString() : null) + "</td>\r\n");
                }
                Add("</tr>\r\n");
            }
            Add(@"
					</tbody>
					<tfoot>
					</tfoot>
						<tr>
							<td class='text'><b>Total</b></td>
");
            foreach (string os in AllOS)
            {
                int total = 0;
                foreach (HealthcheckData data in Report)
                {
                    if (data.OperatingSystem != null)
                    {
                        foreach (var OS in data.OperatingSystem)
                        {
                            if (OS.OperatingSystem == os)
                            {
                                total += OS.NumberOfOccurence;
                                break;
                            }
                        }
                    }
                }
                Add(@"<td class='num'><b>" + total + "</b></td>");
            }
            Add(@"
				</tr>
				</table>
			</div>
		</div>");
            if (SpecificOK.Count > 0)
            {
                Add(@"
		<div class=""row"">
			<div class=""col-md-12 table-responsive"">
				<table class=""table table-striped table-bordered"">
					<thead><tr> 
						<th>Operating System</th>
						<th>Nb</th>
						</tr>
					</thead>
					<tbody>");
                foreach (string os in SpecificOK.Keys)
                {
                    Add("<tr><td class='text'>Nb ");
					AddEncoded(os);
					Add(" : </td><td class='num'>");
					Add(SpecificOK[os]);
					Add("</td></tr>");
                }
                Add(@"
					</tbody>
				</table>
			</div>
		</div>");
            }
            return output;
        }
        #endregion computer

        #region admin
        private void GenerateAdminGroupsInformation()
        {
            Add(@"
		<div class=""row"">
			<div class=""col-md-12 table-responsive"">
				<table class=""table table-striped table-bordered"">
					<thead><tr> 
						<th>Domain</th>
						<th>Group Name</th>
						<th>Nb Admins</th>
						<th>Nb Enabled</th>
						<th>Nb Disabled</th>
						<th>Nb Inactive</th>
						<th>Nb PWd never expire</th>
						<th>Nb can be delegated</th>
						<th>Nb external users</th>");

			Add(@"
						</tr>
					</thead>
					<tbody>
");
            foreach (HealthcheckData data in Report)
            {
                foreach (HealthCheckGroupData group in data.PrivilegedGroups)
                {
                    Add(@"
						<tr>
							<td class='text'>");
					Add(PrintDomain(data.Domain));
					Add(@"</td>
							<td class='text'>");
					AddEncoded(group.GroupName);
					Add(@"</td>
							<td class='num'>");
					Add(group.NumberOfMember);
					Add(@"</td>
							<td class='num'>");
					Add(group.NumberOfMemberEnabled);
					Add(@"</td>
							<td class='num'>");
					Add(group.NumberOfMemberDisabled);
					Add(@"</td>
							<td class='num'>");
					Add(group.NumberOfMemberInactive);
					Add(@"</td>
							<td class='num'>");
					Add(group.NumberOfMemberPwdNeverExpires);
					Add(@"</td>
							<td class='num'>");
					Add(group.NumberOfMemberCanBeDelegated);
					Add(@"</td>
							<td class='num'>");
					Add(group.NumberOfExternalMember);
					Add(@"</td>
						</tr>
");
                }
            }
            Add(@"
					</tbody>
				</table>
			</div>
		</div>
");
        }
        #endregion admin

        #region trust
        private void GenerateTrustInformation()
        {
            List<string> knowndomains = new List<string>();
            GenerateSubSection("Discovered domains");
            Add(@"
		<div class=""row"">
			<div class=""col-md-12 table-responsive"">
				<table class=""table table-striped table-bordered"">
					<thead><tr>
						<th>Domain</th>
						<th>Trust Partner</th>
						<th>Type</th>
						<th>Attribut</th>
						<th>Direction</th>
						<th>SID Filtering active</th>
						<th>TGT Delegation</th>
						<th>Creation</th>
						<th>Is Active ?</th>
						</tr>
					</thead>
					<tbody>
");
            foreach (HealthcheckData data in Report)
            {

                if (!knowndomains.Contains(data.DomainFQDN))
                    knowndomains.Add(data.DomainFQDN);
                data.Trusts.Sort(
                    (HealthCheckTrustData a, HealthCheckTrustData b)
                    =>
                    {
                        return String.Compare(a.TrustPartner, b.TrustPartner);
                    }
                );

                foreach (HealthCheckTrustData trust in data.Trusts)
                {
                    if (!knowndomains.Contains(trust.TrustPartner))
                        knowndomains.Add(trust.TrustPartner);
                    Add(@"
						<tr>
							<td class='text'>" + PrintDomain(data.Domain) + @"</td>
							<td class='text'>" + PrintDomain(trust.Domain) + @"</td>
							<td class='text'>" + TrustAnalyzer.GetTrustType(trust.TrustType) + @"</td>
							<td class='text'>" + TrustAnalyzer.GetTrustAttribute(trust.TrustAttributes) + @"</td>
							<td class='text'>" + TrustAnalyzer.GetTrustDirection(trust.TrustDirection) + @"</td>
							<td class='text'>" + TrustAnalyzer.GetSIDFiltering(trust) + @"</td>
							<td class='text'>" + TrustAnalyzer.GetTGTDelegation(trust) + @"</td>
							<td class='text'>" + trust.CreationDate.ToString("u") + @"</td>
							<td class='text'>" + trust.IsActive + @"</td>
						</tr>
");
                }
            }
            Add(@"
					</tbody>
				</table>
			</div>
		</div>
");
            GenerateSubSection("Other discovered domains");
            Add(@"
		<div class=""row"">
			<div class=""col-md-12 table-responsive"">
				<table class=""table table-striped table-bordered"">
					<thead><tr> 
						<th>From</th>
						<th>Reachable domain</th>
						<th>Via</th>
						<th>Netbios</th>
						<th>Creation date</th>
						</tr>
					</thead>
					<tbody>
");
            foreach (HealthcheckData data in Report)
            {
                foreach (HealthCheckTrustData trust in data.Trusts)
                {
                    if (trust.KnownDomains == null)
                        continue;
                    trust.KnownDomains.Sort((HealthCheckTrustDomainInfoData a, HealthCheckTrustDomainInfoData b)
                        =>
                    {
                        return String.Compare(a.DnsName, b.DnsName);
                    }
                    );
                    foreach (HealthCheckTrustDomainInfoData di in trust.KnownDomains)
                    {
                        if (knowndomains.Contains(di.DnsName))
                            continue;
                        knowndomains.Add(di.DnsName);
                        Add(@"
						<tr>
							<td class='text'>");
						Add(PrintDomain(data.Domain));
						Add(@"</td>
							<td class='text'>");
						AddEncoded(di.DnsName);
						Add(@"</td>
							<td class='text'>");
						AddEncoded(trust.TrustPartner);
						Add(@"</td>
							<td class='text'>");
						AddEncoded(di.NetbiosName);
						Add(@"</td>
							<td class='text'>");
						Add(di.CreationDate);
						Add(@"</td>
						</tr>
");
                    }
                }
            }
            foreach (HealthcheckData data in Report)
            {
                if (data.ReachableDomains != null)
                {
                    foreach (HealthCheckTrustDomainInfoData di in data.ReachableDomains)
                    {
                        if (knowndomains.Contains(di.DnsName))
                            continue;
                        knowndomains.Add(di.DnsName);
                        Add(@"
						<tr>
							<td class='text'>");
						Add(PrintDomain(data.Domain));
						Add(@"</td>
							<td class='text'>");
						AddEncoded(di.DnsName);
						Add(@"</td>
							<td class='text'>Unknown</td>
							<td class='text'>");
						AddEncoded(di.NetbiosName);
						Add(@"</td>
							<td class='text'>Unknown</td>
						</tr>
");
                    }
                }
            }

            Add(@"
					</tbody>
				</table>
			</div>
		</div>
");

            // prepare a SID map to locate unknown account
            SortedDictionary<string, string> sidmap = new SortedDictionary<string, string>();
            GenerateSubSection("SID Map");
            Add(@"
		<div class=""row"">
			<div class=""col-md-12 table-responsive"">
				<table class=""table table-striped table-bordered"">
					<thead><tr>
						<th>Domain</th>
						<th>Domain SID</th>
						</tr>
					</thead>
					<tbody>
");
            foreach (HealthcheckData data in Report)
            {
                if (!sidmap.ContainsKey(data.DomainFQDN) && !String.IsNullOrEmpty(data.DomainSid))
                {
                    sidmap.Add(data.DomainFQDN, data.DomainSid);
                }
                foreach (HealthCheckTrustData trust in data.Trusts)
                {
                    if (!sidmap.ContainsKey(trust.TrustPartner) && !String.IsNullOrEmpty(trust.SID))
                    {
                        sidmap.Add(trust.TrustPartner, trust.SID);
                    }
                    foreach (HealthCheckTrustDomainInfoData di in trust.KnownDomains)
                    {
                        if (!sidmap.ContainsKey(di.DnsName) && !String.IsNullOrEmpty(di.Sid))
                        {
                            sidmap.Add(di.DnsName, di.Sid);
                        }
                    }
                }

            }
            foreach (HealthcheckData data in Report)
            {
                if (data.ReachableDomains != null)
                {
                    foreach (HealthCheckTrustDomainInfoData di in data.ReachableDomains)
                    {
                        if (!sidmap.ContainsKey(di.DnsName) && !String.IsNullOrEmpty(di.Sid))
                        {
                            sidmap.Add(di.DnsName, di.Sid);
                        }
                    }
                }
            }
            foreach (string domain in sidmap.Keys)
            {
                Add(@"
						<tr>
							<td class='text'>");
				AddEncoded(domain);
				Add(@"</td>
							<td class='text'>");
				Add(sidmap[domain]);
				Add(@"</td>
						</tr>
");
            }
            Add(@"
					</tbody>
				</table>
			</div>
		</div>
");
        }
        #endregion trust

        #region anomaly
        private void GenerateAnomalyDetail()
        {
            Add(@"
		<div class=""row"">
			<div class=""col-md-12 table-responsive"">
				<table class=""table table-striped table-bordered"">
					<thead><tr> 
						<th>Domain</th>
						<th>Krbtgt</th>
						<th>AdminSDHolder</th>
						<th>DC with null session</th>
						<th>Smart card account not update</th>
						<th>Date LAPS Installed</th>
						</tr>
					</thead>
					<tbody>
");
            foreach (HealthcheckData data in Report)
            {
                Add(@"
						<tr>
							<td class='text'>" + PrintDomain(data.Domain) + @"</td>
							<td class='text'>" + data.KrbtgtLastChangeDate.ToString("u") + @"</td>
							<td class='num'>" + data.AdminSDHolderNotOKCount + @"</td>
							<td class='num'>" + data.DomainControllerWithNullSessionCount + @"</td>
							<td class='num'>" + data.SmartCardNotOKCount + @"</td>
							<td class='text'>" + (data.LAPSInstalled == DateTime.MaxValue ? "Never" : (data.LAPSInstalled == DateTime.MinValue ? "Not checked" : data.LAPSInstalled.ToString("u"))) + @"</td>
						</tr>
");
            }
            Add(@"
					</tbody>
				</table>
			</div>
		</div>
");
        }
        #endregion anomaly

        #region passwordpolicy
        private void GeneratePasswordPoliciesDetail()
        {
            GenerateSubSection("Password policies");
            Add(@"
		<div class=""row"">
			<div class=""col-md-12 table-responsive"">
				<table class=""table table-striped table-bordered"">
					<thead><tr> 
						<th>Domain</th>
						<th>Policy Name</th>
						<th>Complexity</th>
						<th>Max Password Age</th>
						<th>Min Password Age</th>
						<th>Min Password Length</th>
						<th>Password History</th>
						<th>Reversible Encryption</th>
						<th>Lockout Threshold</th>
						<th>Lockout Duration</th>
						<th>Reset account counter locker after</th>
						</tr>
					</thead>
					<tbody>
");
            foreach (HealthcheckData data in Report)
            {
                if (data.GPPPasswordPolicy != null)
                {
                    foreach (GPPSecurityPolicy policy in data.GPPPasswordPolicy)
                    {
                        Add(@"
						<tr>
							<td class='text'>");
						Add(PrintDomain(data.Domain));
						Add(@"</td>
							<td class='text'>");
						AddEncoded(policy.GPOName);
						Add(@"</td>
							<td class='text'>");
						Add(GetPSOStringValue(policy, "PasswordComplexity"));
						Add(@"</td>
							<td class='num'>");
						Add(GetPSOStringValue(policy, "MaximumPasswordAge"));
						Add(@"</td>
							<td class='num'>");
						Add(GetPSOStringValue(policy, "MinimumPasswordAge"));
						Add(@"</td>
							<td class='num'>");
						Add(GetPSOStringValue(policy, "MinimumPasswordLength"));
						Add(@"</td>
							<td class='num'>");
						Add(GetPSOStringValue(policy, "PasswordHistorySize"));
						Add(@"</td>
							<td class='text'>");
						Add(GetPSOStringValue(policy, "ClearTextPassword"));
						Add(@"</td>
							<td class='num'>");
						Add(GetPSOStringValue(policy, "LockoutBadCount"));
						Add(@"</td>
							<td class='num'>");
						Add(GetPSOStringValue(policy, "LockoutDuration"));
						Add(@"</td>
							<td class='num'>");
						Add(GetPSOStringValue(policy, "ResetLockoutCount"));
						Add(@"</td>
						</tr>
");
                    }
                }
            }
            Add(@"
					</tbody>
				</table>
			</div>
		</div>
");
            GenerateSubSection("Screensaver policies");
            Add(@"
		<div class=""row"">
			<div class=""col-md-12 table-responsive"">
				<table class=""table table-striped table-bordered"">
					<thead><tr> 
						<th>Domain</th>
						<th>Policy Name</th>
						<th>Screensaver enforced</th>
						<th>Password request</th>
						<th>Start after (seconds)</th>
						<th>Grace Period (seconds)</th>
						</tr>
					</thead>
					<tbody>
");
            foreach (HealthcheckData data in Report)
            {
                if (data.GPPPasswordPolicy != null)
                {
                    foreach (GPPSecurityPolicy policy in data.GPOScreenSaverPolicy)
                    {
                        string scrActive = GetPSOStringValue(policy, "ScreenSaveActive");
                        string scrSecure = GetPSOStringValue(policy, "ScreenSaverIsSecure");
                        string scrTimeOut = GetPSOStringValue(policy, "ScreenSaveTimeOut");
                        string scrGrace = GetPSOStringValue(policy, "ScreenSaverGracePeriod");

                        Add(@"
						<tr>
							<td class='text'>");
						Add(PrintDomain(data.Domain));
						Add(@"</td>
							<td class='text'>");
						AddEncoded(policy.GPOName);
						Add(@"</td>
							<td class='num'>");
						Add(scrActive);
						Add(@"</td>
							<td class='num'>");
						Add(scrSecure);
						Add(@"</td>
							<td class='num'>");
						Add(scrTimeOut);
						Add(@"</td>
							<td class='text'>");
						Add(scrGrace);
						Add(@"</td>
						</tr>
");
                    }
                }
            }
            Add(@"
					</tbody>
				</table>
			</div>
		</div>
");
            GenerateSubSection("Security settings");
            Add(@"
		<div class=""row"">
			<div class=""col-md-12 table-responsive"">
				<table class=""table table-striped table-bordered"">
					<thead><tr> 
						<th>Domain</th>
						<th>Policy Name</th>
						<th>Setting</th>
						<th>Value</th>
					</thead>
					<tbody>");
            foreach (HealthcheckData data in Report)
            {
                if (data.GPOLsaPolicy != null)
                {
                    foreach (GPPSecurityPolicy policy in data.GPOLsaPolicy)
                    {
                        foreach (GPPSecurityPolicyProperty property in policy.Properties)
                        {
                            Add(@"
						<tr>
							<td class='text'>");
							Add(PrintDomain(data.Domain));
							Add(@"</td>
							<td class='text'>");
							AddEncoded(policy.GPOName);
							Add(@"</td>
							<td class='text'>");
							Add(GetLinkForLsaSetting(property.Property));
							Add(@"</td>
							<td class='text'>");
							Add(GetLsaSettingsValue(property.Property, property.Value));
							Add(@"</td>
						</tr>
");
                        }
                    }
                }
            }
            Add(@"
					</tbody>
				</table>
			</div>
		</div>
");
        }
        #endregion passwordpolicy

        #region gpo detail
        private void GenerateGPODetail()
        {
            GenerateSubSection("Obfuscated Password");
            Add(@"
		<div class=""row"">
			<div class=""col-md-12 table-responsive"">
				<table class=""table table-striped table-bordered"">
					<thead><tr> 
						<th>Domain</th>
						<th>GPO Name</th>
						<th>Password origin</th>
						<th>UserName</th>
						<th>Password</th>
						<th>Changed</th>
						<th>Other</th>
						</tr>
					</thead>
					<tbody>
");
            foreach (HealthcheckData data in Report)
            {
                foreach (GPPPassword password in data.GPPPassword)
                {
                    Add(@"
						<tr>
							<td class='text'>");
					Add(PrintDomain(data.Domain));
					Add(@"</td>
							<td class='text'>");
					AddEncoded(password.GPOName);
					Add(@"</td>
							<td class='text'>");
					AddEncoded(password.Type);
					Add(@"</td>
							<td class='text'>");
					AddEncoded(password.UserName);
					Add(@"</td>
							<td class='text'>");
					AddEncoded(password.Password);
					Add(@"</td>
							<td class='text'>");
					Add(password.Changed);
					Add(@"</td>
							<td class='text'>");
					AddEncoded(password.Other);
					Add(@"</td>
						</tr>
");
                }
            }
            Add(@"
					</tbody>
				</table>
			</div>
		</div>
");
        }
        #endregion gpo detail

        new string PrintDomain(DomainKey key)
        {
            string label = PrintDomainLabel(key);
            if (GetUrlCallback == null)
                return label;
            string htmlData = GetUrlCallback(key, label);
            if (String.IsNullOrEmpty(htmlData))
                return label;
            return htmlData;
        }

        string PrintDomainLabel(DomainKey key)
        {
            if (HasDomainAmbigousName != null)
            {
                if (HasDomainAmbigousName(key))
                    return key.ToString();
            }
            else if (Report.HasDomainAmbigiousName(key))
                return key.ToString();
            return key.DomainName;
        }
    }
}
