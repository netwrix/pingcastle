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

namespace PingCastle.Healthcheck
{
    public class HealthCheckReportConsolidation : HealthCheckReportBase
    {
        private HealthcheckDataCollection consolidation;

        
        public HealthCheckReportConsolidation(HealthcheckDataCollection consolidation)
        {
            this.consolidation = consolidation;
        }

        protected override string GenerateFooterInformation()
        {
            return null;
        }

        protected override string GenerateTitleInformation()
        {
            return "PingCastle Consolidation report - " + DateTime.Now.ToString("yyyy-MM-dd");
        }

        protected override string GenerateHeaderInformation()
        {
            return GetStyleSheetTheme() + GetStyleSheet();
        }

        public static string GetStyleSheet()
        {
            return @"
<!-- Custom styles for this template -->
    <style>
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
</style>
<link href=""data:image/x-icon;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAE10lEQVRYw71XfWwTdRhet4xBssFigMja61rafbK5bGFuiqh1ISaMP2QI++jaXtvUZGKIigUkUTTzmwUxIQtRYBZHr3e9rjYOY4zLlprMEDROJagZAzEgMYiTZJvr7zrmc0cHXekXxfWSJ9f2rvc8977P+76/X0YGDsKubiSuwh2ELy8SfPVZGek+QG4hTjkhDPUrPh8grOYJwhXlCV9tSZMAdnUDBEwRZ8HsTcivE0bxJQR1QEyJ0L8+e2EFcEWlhJFfuS3gFoIQcpG4VMcRmUbcd58wqJeJ/2FYfhGwDegG9gKrUhfAly4H0UgUAWGQTyAiw8Sl3kv6qpaDcDMwDswCQaCH5fqWpCRA8D2YQ1zK/vgCQnCprgv9j9aD8FCIfA4XAGVqAj7fIBrxg6QEMIop4i7ZADI7IIQJ8AP5qaeBobYnJ0D5O6LwsIvzrADhQWAUGHJxfEOA1TwE09LEU6EUPnsk8y4rQfO0VIqxyW+IHgh4KnVWs6HaaDI/85J9t+Z4r1Pl599ZSbjiRlz/Ec8QcD4rRdRdrCOcNlcYaE6mErS1qITxGAYkeKDzam9VsdlibWptaz8DCPp2488Wq20H8daUg/TCndGS/wN8IUWXK9YSvix2k4NaCvkdi0I+DvJ9gwcbKIOR3gXiqy2t+tk5QITvoqNODZLRONELSs9mqI/wohshJl8YbJPNF+BZk4sb/BGGOw/y1lefb1WD6DDIp8LJQwK+P9bZrIQ3hpLykFTOiq/x3F1o/QW3K+GkLhPqGgir3omS9OOmoQCrXW+hjTVtesMAyIKR5CJw7fL2DlsZxDuSEyAhAAE9SIk8I9TVZHC1Fmc9zrpL7k3yPx1rCvTthkYx39GI54Drk7TZCrNp3k2uiqSUvoJSXnbr7UG6FuQjoY4mdrcXOp59biXe7nQ88hBm4A0TBJgR3pkE5KOYO83EW50zL/8gfDuiq/105NjHFPL7aRICZlGSL2NOPCblNzr5jJhSvHmtwFfI7qgAEL4ZIWDkaI8DKTAyILiRSEC7weSYYCtLQHI5Cvk0DNoDbxXic/QSBGEF8A0wDVwBbKc+sS2maVpsOJ1IxQiIpmMJgFC//9CTqATFdxGO/xu/7YG5l8VtQvCAKKKAdfdtQkutHufqNchVN1S/9i+jrurc2aI0muitIDoBwkuRUYHAM512Won7D4DwN8kLDDWGkG8F+aK7XB2pWvCAb6W8ie3XiXUCo2Dxu/7c0ZpCq9n0AEJuB+mwWAHAWXx/an/X+3l+91v3T/Loii7Vi3B5vdD/eGYKqyP1nhhGQi4VPyAyXeLQ+XBfE2WizRtNtEWsoHWAFzgNvM5xHDqdPuXl2ZbEQ0l+DSE+Cedv7uOZfJAOhBk4AFjuZX24VjJPUouTQqfXfUIFwvMRVdR1L+tDcSidS66rUcNjfNsqELrDyCdg6m2pC3CX5krDIvFQgSeobuKpXIq1YBmI3wN6ARoClqQsQPDVZUFAbwLyvzCwdmOEL537H0pYxvHeLAj4XzYq++P0c2xeVE2o7+wF3KiobaE+ENHPqUFcq8Ucly3wVk2lQ5gn5/UAp/ywaNDgKXsatmpckThY/gitiq5J+Xap8tK3WeXLb+6UGMUvWC03EV9ddkY6D2y9cpDrN9CU1kHAgub7P7CsZhuj7eUMAAAAAElFTkSuQmCC"" rel=""icon"" type=""image/x-icon"" />
";
        }

        protected override void Hook(ref string html)
        {
            html = html.Replace("<body>", @"<body data-spy=""scroll"" data-target="".navbar"" data-offset=""50"">");
        }

        protected override string GenerateBodyInformation()
        {
            Version version = Assembly.GetExecutingAssembly().GetName().Version;
            string versionString = version.ToString(4);
#if DEBUG
            versionString += " Beta";
#endif

            string output = @"
<nav class=""navbar navbar-default navbar-fixed-top"" role=""navigation"">
    <div class=""container-fluid"">
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
                    <a aria-expanded=""false"" role=""button"" href=""#"">Consolidation</a>
                </li>
				<li>
					<a aria-expanded=""false"" role=""button"" href=""#"">" + DateTime.Now.ToString("yyyy-MM-dd") + @"</a>
				</li>
			</ul>
		</div>
	</div>
</nav>
<div id=""wrapper"" class=""container-fluid well"">
	<noscript>
		<div class=""alert alert-warning"">
			<p>PingCastle reports work best with Javascript enabled.</p>
		</div>
	</noscript>
<div class=""row""><div class=""col-lg-12""><h1>Consolidation</h1>
			<h3>Date: " + DateTime.Now.ToString("yyyy-MM-dd") + @" - Engine version: " + versionString + @"</h3>
</div></div>
" + GenerateContent() + @"
</div>
";
            return output;
        }

        private static string GenerateId(string title)
        {
            return "section" + title.Replace(" ", "");
        }

        protected void GenerateSectionFluid(string title, GenerateContentDelegate generateContent, string selectedTab, bool defaultIfTabEmpty = false)
        {
            string id = GenerateId(title);
            bool isActive = (String.IsNullOrEmpty(selectedTab) ? defaultIfTabEmpty : selectedTab == id);
            Add(@"
<!-- Section ");
            Add(title);
            Add(@" -->
<div class=""tab-pane");
            if (isActive)
                Add(" active");
            Add(@""" id=""");
            Add(id);
            Add(@""">
	<div class=""starter-template"">
		<div class=""row""><div class=""col-lg-12"">
			<h1>");
            Add(title);
            Add(@"</h1>
		</div></div>
");
            generateContent();
            Add(@"
	</div>
</div>
<!-- Section " + title + @" end -->
");
        }

        public string GenerateContent(string selectedTab = null)
        {
            Add(@"
<div class=""panel with-nav-tabs panel-default"">
    <div class=""panel-heading"">
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
    <div class=""panel-body"">
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
            return sb.ToString(); ;
        }

        private void GenerateTabHeader(string title, string selectedTab, bool defaultIfTabEmpty = false)
        {
            string id = GenerateId(title);
            bool isActive = (String.IsNullOrEmpty(selectedTab) ? defaultIfTabEmpty : selectedTab == id);
            Add(@"<li");
            if (isActive)
                Add(@" class=""active""");
            Add(@"><a href=""#");
            Add(id);
            Add(@""" role=""tab"" data-toggle=""tab"">");
            Add(title);
            Add("</a></li>");
        }

        private void GenerateRulesMatched()
        {
            Add(@"
		<div class=""row"">
			<div class=""col-md-12 table-responsive"">
				<table class=""table table-striped table-bordered sortable-theme-bootstrap"" data-sortable="""">
					<thead><TR> 
						<Th>Domain</Th>
						<Th>Category</Th>
						<Th>Rule</Th>
						<th>Score</th>
						<Th>Description</Th>
						<Th>Rationale</Th>
						</TR>
					</thead>
					<tbody>
");
            foreach (HealthcheckData data in consolidation)
            {
                foreach (HealthcheckRiskRule rule in data.RiskRules)
                {
                    Add(@"
						<TR>
							<TD class='text'>" + PrintDomain(data.Domain) + @"</TD>
							<TD class='text'>" + rule.Category + @"</TD>
							<TD class='text'>" + rule.RiskId + @"</TD>
							<TD class='num'>" + rule.Points + @"</TD>
							<TD class='text'>" + HealthcheckRules.GetRuleDescription(rule.RiskId) + @"</TD>
							<TD class='text'>" + rule.Rationale + @"</TD>
						</TR>");
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
            foreach (var data in consolidation)
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
            GenerateRiskModelPanel();
            GenerateIndicatorsTable();
        }

        void GenerateRiskModelPanel()
        {
            Add(@"
		<div class=""row""><div class=""col-lg-12"">
			<a data-toggle=""collapse"" data-target=""#riskModel"">
				<h2>Risk model</h2>
			</a>
		</div></div>
		<div class=""row collapse in"" id=""riskModel"">
			<div class=""col-md-12 table-responsive"">
				<table class=""model_table"">
					<thead><tr><th>Staled Objects</th><th>Privileged accounts</th><th>Trusts</th><th>Anomalies</th></tr></thead>
					<tbody>
");
            var riskmodel = new Dictionary<HealthcheckRiskRuleCategory, List<HealthcheckRiskModelCategory>>();
            foreach (HealthcheckRiskRuleCategory category in Enum.GetValues(typeof(HealthcheckRiskRuleCategory)))
            {
                riskmodel[category] = new List<HealthcheckRiskModelCategory>();
            }
            for (int j = 0; j < 4; j++)
            {
                for (int i = 0; ; i++)
                {
                    int id = (1000 * j + 1000 + i);
                    if (Enum.IsDefined(typeof(HealthcheckRiskModelCategory), id))
                    {
                        riskmodel[(HealthcheckRiskRuleCategory)j].Add((HealthcheckRiskModelCategory)id);
                    }
                    else
                        break;
                }
            }
            foreach (HealthcheckRiskRuleCategory category in Enum.GetValues(typeof(HealthcheckRiskRuleCategory)))
            {
                riskmodel[category].Sort(
                                        (HealthcheckRiskModelCategory a, HealthcheckRiskModelCategory b) =>
                                        {
                                            return GetEnumDescription(a).CompareTo(GetEnumDescription(b));
                                        });
            }
            for (int i = 0; ; i++)
            {
                string line = "<tr>";
                bool HasValue = false;
                foreach (HealthcheckRiskRuleCategory category in Enum.GetValues(typeof(HealthcheckRiskRuleCategory)))
                {
                    if (i < riskmodel[category].Count)
                    {
                        HasValue = true;
                        HealthcheckRiskModelCategory model = riskmodel[category][i];
                        int score = 0;
                        int numrules = 0;
                        int numImpacted = 0;
                        List<HealthcheckRiskRule> rulematched = new List<HealthcheckRiskRule>();
                        foreach (HealthcheckData data in consolidation)
                        {
                            bool impactedDomain = false;
                            foreach (HealthcheckRiskRule rule in data.RiskRules)
                            {
                                if (rule.Model == model)
                                {
                                    impactedDomain = true;
                                    numrules++;
                                    score += rule.Points;
                                    rulematched.Add(rule);
                                }
                            }
                            if (impactedDomain)
                                numImpacted++;
                        }
                        string tdclass = "";
                        if (numrules == 0)
                        {
                            tdclass = "model_good";
                        }
                        else if (score == 0)
                        {
                            tdclass = "model_info";
                        }
                        else if (score <= 10 * consolidation.Count)
                        {
                            tdclass = "model_toimprove";
                        }
                        else if (score <= 30 * consolidation.Count)
                        {
                            tdclass = "model_warning";
                        }
                        else
                        {
                            tdclass = "model_danger";
                        }
                        string tooltip = (numImpacted > 0 ? " Impacted domains: " + numImpacted + " Rules: " + numrules + " Average Score: " + (score / consolidation.Count) : "No domain impacted");
                        string tooltipdetail = null;
                        string modelstring = GetEnumDescription(model);
                        rulematched.Sort((HealthcheckRiskRule a, HealthcheckRiskRule b)
                            =>
                        {
                            return a.Points.CompareTo(b.Points);
                        });
                        foreach (var rule in rulematched)
                        {
                            tooltipdetail += rule.Rationale + "<br>";
                        }
                        line += "<td class=\"model_cell " + tdclass + "\"><div class=\"div_model\" placement=\"auto right\" data-toggle=\"popover\" title=\"" +
                            tooltip + "\" data-html=\"true\" data-content=\"" +
                            (String.IsNullOrEmpty(tooltipdetail) ? "No rule matched" : "<p>" + tooltipdetail + "</p>") + "\"><span class=\"small\">" + modelstring + "</span></div></td>";
                    }
                    else
                        line += "<td class=\"model_empty_cell\"></td>";
                }
                line += "</tr>";
                if (HasValue)
                    Add(line);
                else
                    break;
            }
            Add(@"
					</tbody>
				</table>
			</div>
			<div class=""col-md-12"" id=""maturityModel"">
		Legend: <br>
			<i class=""risk_model_none"">&nbsp;</i> score is 0 - no risk identified but some improvements detected<br>
			<i class=""risk_model_low"">&nbsp;</i> score between 1 and 10  - a few actions have been identified<br>
			<i class=""risk_model_medium"">&nbsp;</i> score between 10 and 30 - rules should be looked with attention<br>
			<i class=""risk_model_high"">&nbsp;</i> score higher than 30 - major risks identified
			</div>
		</div>");
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
				<table class=""table table-striped table-bordered sortable-theme-bootstrap"" data-sortable="""">
				<thead><TR> 
					<Th>Domain</Th>
					<Th>Domain Risk Level</Th>
					<Th>Stale objects</Th>
					<Th>Privileged accounts</Th>
					<Th>Trusts</Th>
					<Th>Anomalies</Th>
					<Th>Generated</Th>
					</TR>
				</thead>
				<tbody>
");
            foreach (HealthcheckData data in consolidation)
            {
                Add(@"
					<TR>
						<TD class='text'>" + PrintDomain(data.Domain) + @"</TD>
						<TD class='num'>" + data.GlobalScore + @"</TD>
						<TD class='num'>" + data.StaleObjectsScore + @"</TD>
						<TD class='num'>" + data.PrivilegiedGroupScore + @"</TD>
						<TD class='num'>" + data.TrustScore + @"</TD>
						<TD class='num'>" + data.AnomalyScore + @"</TD>
						<TD class='text'>" + data.GenerationDate.ToString("u") + @"</TD>
					</TR>");
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
				<table class=""table table-striped table-bordered sortable-theme-bootstrap"" data-sortable="""">
					<thead><TR> 
						<Th>Domain</Th>
						<Th>Netbios Name</Th>
						<Th>Domain Functional Level</Th>
						<Th>Forest Functional Level</Th>
						<Th>Creation date</th>
						<Th>Nb DC</Th>
						<th>Engine</th>
						<th>Level</th>
						</TR>
					</thead>
					<tbody>
");
            foreach (HealthcheckData data in consolidation)
            {
                Add(@"
						<TR>
							<TD class='text'>" + PrintDomain(data.Domain) + @"</TD>
							<TD class='text'>" + Encode(data.NetBIOSName) + @"</TD>
							<TD class='text'>" + DecodeDomainFunctionalLevel(data.DomainFunctionalLevel) + @"</TD>
							<TD class='text'>" + DecodeForestFunctionalLevel(data.ForestFunctionalLevel) + @"</TD>
							<TD class='text'>" + data.DomainCreation.ToString("u") + @"</TD>
							<TD class='num'>" + data.NumberOfDC + @"</TD>
							<TD class='text'>" + data.EngineVersion + @"</TD>
							<TD class='text'>" + data.Level + @"</TD>
						</TR>");
            }
            Add(@"
					</tbody>
					<tfoot>
						<tr>
							<td class='text'><b>Total</b></td>
							<td class='num'>" + consolidation.Count + @"</td>
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
				<table class=""table table-striped table-bordered sortable-theme-bootstrap"" data-sortable="""">
				<thead><tr>
					<Th>Domain</Th>
					<Th>Nb User Accounts</Th>
					<Th>Nb Enabled</Th>
					<Th>Nb Disabled</Th>
					<Th>Nb Active</Th>
					<Th>Nb Inactive</Th>
					<Th>Nb Locked</Th>
					<Th>Nb pwd never Expire</Th>
					<Th>Nb SidHistory</Th>
					<Th>Nb Bad PrimaryGroup</Th>
					<Th>Nb Password not Req.</Th>
					<Th>Nb Des enabled.</Th>
					<Th>Nb Trusted delegation</Th>
					<Th>Nb Reversible password</Th>
					</TR>
				</thead>
				<tbody>
");
            HealthcheckAccountData total = new HealthcheckAccountData();
            foreach (HealthcheckData data in consolidation)
            {
                total.Add(data.UserAccountData);
                Add(@"
					<TR>
						<TD class='text'>" + PrintDomain(data.Domain) + @"</TD>
						<TD class='num'>" + data.UserAccountData.Number + @"</TD>
						<TD class='num'>" + data.UserAccountData.NumberEnabled + @"</TD>
						<TD class='num'>" + data.UserAccountData.NumberDisabled + @"</TD>
						<TD class='num'>" + data.UserAccountData.NumberActive + @"</TD>
						<TD class='num'>" + data.UserAccountData.NumberInactive + @"</TD>
						<TD class='num'>" + data.UserAccountData.NumberLocked + @"</TD>
						<TD class='num'>" + data.UserAccountData.NumberPwdNeverExpires + @"</TD>
						<TD class='num'>" + data.UserAccountData.NumberSidHistory + @"</TD>
						<TD class='num'>" + data.UserAccountData.NumberBadPrimaryGroup + @"</TD>
						<TD class='num'>" + data.UserAccountData.NumberPwdNotRequired + @"</TD>
						<TD class='num'>" + data.UserAccountData.NumberDesEnabled + @"</TD>
						<TD class='num'>" + data.UserAccountData.NumberTrustedToAuthenticateForDelegation + @"</TD>
						<TD class='num'>" + data.UserAccountData.NumberReversibleEncryption + @"</TD>
					</TR>");
            }
            Add(@"
				</tbody>
				<tfoot>
					<TR>
						<TD class='text'><b>Total</b></TD>
						<TD class='num'><b>" + total.Number + @"</b></TD>
						<TD class='num'><b>" + total.NumberEnabled + @"</b></TD>
						<TD class='num'><b>" + total.NumberDisabled + @"</b></TD>
						<TD class='num'><b>" + total.NumberActive + @"</b></TD>
						<TD class='num'><b>" + total.NumberInactive + @"</b></TD>
						<TD class='num'><b>" + total.NumberLocked + @"</b></TD>
						<TD class='num'><b>" + total.NumberPwdNeverExpires + @"</b></TD>
						<TD class='num'><b>" + total.NumberSidHistory + @"</b></TD>
						<TD class='num'><b>" + total.NumberBadPrimaryGroup + @"</b></TD>
						<TD class='num'><b>" + total.NumberPwdNotRequired + @"</b></TD>
						<TD class='num'><b>" + total.NumberDesEnabled + @"</b></TD>
						<TD class='num'><b>" + total.NumberTrustedToAuthenticateForDelegation + @"</b></TD>
						<TD class='num'><b>" + total.NumberReversibleEncryption + @"</b></TD>
					</TR>
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
				<table class=""table table-striped table-bordered sortable-theme-bootstrap"" data-sortable="""">
				<thead><TR> 
					<Th>Domain</Th>
					<Th>Nb Computer Accounts</Th>
					<Th>Nb Enabled</Th>
					<Th>Nb Disabled</Th>
					<Th>Nb Active</Th>
					<Th>Nb Inactive</Th>
					<Th>Nb SidHistory</Th>
					<Th>Nb Bad PrimaryGroup</Th>
					<Th>Nb Trusted delegation</Th>
					<Th>Nb Reversible password</Th>
					</TR>
				</thead>
				<tbody>
");
            HealthcheckAccountData total = new HealthcheckAccountData();
            foreach (HealthcheckData data in consolidation)
            {
                total.Add(data.ComputerAccountData);
                Add(@"
					<TR>
						<TD class='text'>" + PrintDomain(data.Domain) + @"</TD>
						<TD class='num'>" + data.ComputerAccountData.Number + @"</TD>
						<TD class='num'>" + data.ComputerAccountData.NumberEnabled + @"</TD>
						<TD class='num'>" + data.ComputerAccountData.NumberDisabled + @"</TD>
						<TD class='num'>" + data.ComputerAccountData.NumberActive + @"</TD>
						<TD class='num'>" + data.ComputerAccountData.NumberInactive + @"</TD>
						<TD class='num'>" + data.ComputerAccountData.NumberSidHistory + @"</TD>
						<TD class='num'>" + data.ComputerAccountData.NumberBadPrimaryGroup + @"</TD>
						<TD class='num'>" + data.ComputerAccountData.NumberTrustedToAuthenticateForDelegation + @"</TD>
						<TD class='num'>" + data.ComputerAccountData.NumberReversibleEncryption + @"</TD>
					</TR>");
            }
            Add(@"
				</tbody>
				<tfoot>
				<TR>
				<TD class='text'><b>Total</b></TD>
				<TD class='num'><b>" + total.Number + @"</b></TD>
				<TD class='num'><b>" + total.NumberEnabled + @"</b></TD>
				<TD class='num'><b>" + total.NumberDisabled + @"</b></TD>
				<TD class='num'><b>" + total.NumberActive + @"</b></TD>
				<TD class='num'><b>" + total.NumberInactive + @"</b></TD>
				<TD class='num'><b>" + total.NumberSidHistory + @"</b></TD>
				<TD class='num'><b>" + total.NumberBadPrimaryGroup + @"</b></TD>
				<TD class='num'><b>" + total.NumberTrustedToAuthenticateForDelegation + @"</b></TD>
				<TD class='num'><b>" + total.NumberReversibleEncryption + @"</b></TD>
				</TR>
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
            foreach (HealthcheckData data in consolidation)
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
				<table class=""table table-striped table-bordered sortable-theme-bootstrap"" data-sortable="""">
					<thead><TR> 
						<Th>Domain</Th>
");
            foreach (string os in AllOS)
            {
                Add("<Th>" + Encode(os) + "</Th>\r\n");
            }
            Add(@"
						</TR>
					</thead>
					<tbody>
");
            // maybe not the most perfomant algorithm (n^4) but there is only a few domains to consolidate
            foreach (HealthcheckData data in consolidation)
            {
                Add(@"<TR>
<TD class='text'>" + PrintDomain(data.Domain) + @"</TD>
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
                    Add("<TD class='num'>" + (numberOfOccurence >= 0 ? numberOfOccurence.ToString() : null) + "</TD>\r\n");
                }
                Add("</TR>\r\n");
            }
            Add(@"
					</tbody>
					<tfoot>
					</tfoot>
						<TR>
							<TD class='text'><b>Total</b></TD>
");
            foreach (string os in AllOS)
            {
                int total = 0;
                foreach (HealthcheckData data in consolidation)
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
				<table class=""table table-striped table-bordered sortable-theme-bootstrap"" data-sortable="""">
					<thead><TR> 
						<Th>Operating System</Th>
						<Th>Nb</Th>
						</TR>
					</thead>
					<tbody>");
                foreach (string os in SpecificOK.Keys)
                {
                    Add("<TR><TD class='text'>Nb " + Encode(os) + " : </TD><TD class='num'>" + SpecificOK[os] + "</TD></TR>");
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
				<table class=""table table-striped table-bordered sortable-theme-bootstrap"" data-sortable="""">
					<thead><TR> 
						<Th>Domain</th>
						<Th>Group Name</Th>
						<Th>Nb Admins</Th>
						<Th>Nb Enabled</Th>
						<Th>Nb Disabled</Th>
						<Th>Nb Inactive</Th>
						<Th>Nb PWd never expire</Th>
						<Th>Nb can be delegated</Th>
						<Th>Nb external users</Th>
						</TR>
					</thead>
					<tbody>
");
            foreach (HealthcheckData data in consolidation)
            {
                foreach (HealthCheckGroupData group in data.PrivilegedGroups)
                {
                    Add(@"
						<TR>
							<TD class='text'>" + PrintDomain(data.Domain) + @"</TD>
							<TD class='text'>" + Encode(group.GroupName) + @"</TD>
							<TD class='num'>" + group.NumberOfMember + @"</TD>
							<TD class='num'>" + group.NumberOfMemberEnabled + @"</TD>
							<TD class='num'>" + group.NumberOfMemberDisabled + @"</TD>
							<TD class='num'>" + group.NumberOfMemberInactive + @"</TD>
							<TD class='num'>" + group.NumberOfMemberPwdNeverExpires + @"</TD>
							<TD class='num'>" + group.NumberOfMemberCanBeDelegated + @"</TD>
							<TD class='num'>" + group.NumberOfExternalMember + @"</TD>
						</TR>
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
				<table class=""table table-striped table-bordered sortable-theme-bootstrap"" data-sortable="""">
					<thead><TR>
						<Th>Domain</Th>
						<Th>Trust Partner</Th>
						<Th>Type</Th>
						<Th>Attribut</Th>
						<Th>Direction</Th>
						<Th>SID Filtering active</Th>
						<Th>Creation</Th>
						<Th>Is Active ?</Th>
						</TR>
					</thead>
					<tbody>
");
            foreach (HealthcheckData data in consolidation)
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
						<TR>
							<TD class='text'>" + PrintDomain(data.Domain) + @"</TD>
							<TD class='text'>" + PrintDomain(trust.Domain) + @"</TD>
							<TD class='text'>" + TrustAnalyzer.GetTrustType(trust.TrustType) + @"</TD>
							<TD class='text'>" + TrustAnalyzer.GetTrustAttribute(trust.TrustAttributes) + @"</TD>
							<TD class='text'>" + TrustAnalyzer.GetTrustDirection(trust.TrustDirection) + @"</TD>
							<TD class='text'>" + TrustAnalyzer.GetSIDFiltering(trust) + @"</TD>
							<TD class='text'>" + trust.CreationDate.ToString("u") + @"</TD>
							<TD class='text'>" + trust.IsActive + @"</TD>
						</TR>
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
				<table class=""table table-striped table-bordered sortable-theme-bootstrap"" data-sortable="""">
					<thead><TR> 
						<Th>From</Th>
						<Th>Reachable domain</Th>
						<Th>Via</Th>
						<Th>Netbios</Th>
						<Th>Creation date</Th>
						</TR>
					</thead>
					<tbody>
");
            foreach (HealthcheckData data in consolidation)
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
						<TR>
							<TD class='text'>" + PrintDomain(data.Domain) + @"</TD>
							<TD class='text'>" + Encode(di.DnsName) + @"</TD>
							<TD class='text'>" + Encode(trust.TrustPartner) + @"</TD>
							<TD class='text'>" + Encode(di.NetbiosName) + @"</TD>
							<TD class='text'>" + di.CreationDate.ToString("u") + @"</TD>
						</TR>
");
                    }
                }
            }
            foreach (HealthcheckData data in consolidation)
            {
                if (data.ReachableDomains != null)
                {
                    foreach (HealthCheckTrustDomainInfoData di in data.ReachableDomains)
                    {
                        if (knowndomains.Contains(di.DnsName))
                            continue;
                        knowndomains.Add(di.DnsName);
                        Add(@"
						<TR>
							<TD class='text'>" + PrintDomain(data.Domain) + @"</TD>
							<TD class='text'>" + Encode(di.DnsName) + @"</TD>
							<TD class='text'>Unknown</TD>
							<TD class='text'>" + Encode(di.NetbiosName) + @"</TD>
							<TD class='text'>Unknown</TD>
						</TR>
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
				<table class=""table table-striped table-bordered sortable-theme-bootstrap"" data-sortable="""">
					<thead><TR>
						<Th>Domain</Th>
						<Th>Domain SID</Th>
						</TR>
					</thead>
					<tbody>
");
            foreach (HealthcheckData data in consolidation)
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
            foreach (HealthcheckData data in consolidation)
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
						<TR>
							<TD class='text'>" + Encode(domain) + @"</TD>
							<TD class='text'>" + sidmap[domain] + @"</TD>
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
				<table class=""table table-striped table-bordered sortable-theme-bootstrap"" data-sortable="""">
					<thead><TR> 
						<Th>Domain</Th>
						<Th>Krbtgt</Th>
						<Th>AdminSDHolder</Th>
						<th>DC with null session</th>
						<th>Smart card account not update</th>
						<th>Date LAPS Installed</th>
						</TR>
					</thead>
					<tbody>
");
            foreach (HealthcheckData data in consolidation)
            {
                Add(@"
						<TR>
							<TD class='text'>" + PrintDomain(data.Domain) + @"</TD>
							<TD class='text'>" + data.KrbtgtLastChangeDate.ToString("u") + @"</TD>
							<TD class='num'>" + data.AdminSDHolderNotOKCount + @"</TD>
							<TD class='num'>" + data.DomainControllerWithNullSessionCount + @"</TD>
							<TD class='num'>" + data.SmartCardNotOKCount + @"</TD>
							<TD class='text'>" + (data.LAPSInstalled == DateTime.MaxValue ? "Never" : (data.LAPSInstalled == DateTime.MinValue ? "Not checked" : data.LAPSInstalled.ToString("u"))) + @"</TD>
						</TR>
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
				<table class=""table table-striped table-bordered sortable-theme-bootstrap"" data-sortable="""">
					<thead><TR> 
						<Th>Domain</Th>
						<Th>Policy Name</Th>
						<Th>Complexity</Th>
						<Th>Max Password Age</Th>
						<Th>Min Password Age</Th>
						<Th>Min Password Length</Th>
						<Th>Password History</Th>
						<Th>Reversible Encryption</Th>
						<Th>Lockout Threshold</Th>
						<Th>Lockout Duration</Th>
						<Th>Reset account counter locker after</Th>
						</TR>
					</thead>
					<tbody>
");
            foreach (HealthcheckData data in consolidation)
            {
                if (data.GPPPasswordPolicy != null)
                {
                    foreach (GPPSecurityPolicy policy in data.GPPPasswordPolicy)
                    {
                        Add(@"
						<TR>
							<TD class='text'>" + PrintDomain(data.Domain) + @"</TD>
							<TD class='text'>" + Encode(policy.GPOName) + @"</TD>
							<TD class='text'>" + GetPSOStringValue(policy, "PasswordComplexity") + @"</TD>
							<TD class='num'>" + GetPSOStringValue(policy, "MaximumPasswordAge") + @"</TD>
							<TD class='num'>" + GetPSOStringValue(policy, "MinimumPasswordAge") + @"</TD>
							<TD class='num'>" + GetPSOStringValue(policy, "MinimumPasswordLength") + @"</TD>
							<TD class='num'>" + GetPSOStringValue(policy, "PasswordHistorySize") + @"</TD>
							<TD class='text'>" + GetPSOStringValue(policy, "ClearTextPassword") + @"</TD>
							<TD class='num'>" + GetPSOStringValue(policy, "LockoutBadCount") + @"</TD>
							<TD class='num'>" + GetPSOStringValue(policy, "LockoutDuration") + @"</TD>
							<TD class='num'>" + GetPSOStringValue(policy, "ResetLockoutCount") + @"</TD>
						</TR>
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
				<table class=""table table-striped table-bordered sortable-theme-bootstrap"" data-sortable="""">
					<thead><TR> 
						<Th>Domain</Th>
						<Th>Policy Name</Th>
						<Th>Screensaver enforced</Th>
						<Th>Password request</Th>
						<Th>Start after (seconds)</Th>
						<Th>Grace Period (seconds)</Th>
						</TR>
					</thead>
					<tbody>
");
            foreach (HealthcheckData data in consolidation)
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
						<TR>
							<TD class='text'>" + PrintDomain(data.Domain) + @"</TD>
							<TD class='text'>" + Encode(policy.GPOName) + @"</TD>
							<TD class='num'>" + scrActive + @"</TD>
							<TD class='num'>" + scrSecure + @"</TD>
							<TD class='num'>" + scrTimeOut + @"</TD>
							<TD class='text'>" + scrGrace + @"</TD>
						</TR>
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
            GenerateSubSection("LSA settings");
            Add(@"
		<div class=""row"">
			<div class=""col-md-12 table-responsive"">
				<table class=""table table-striped table-bordered sortable-theme-bootstrap"" data-sortable="""">
					<thead><TR> 
						<Th>Domain</Th>
						<Th>Policy Name</Th>
						<Th>Setting</Th>
						<Th>Value</Th>
					</thead>
					<tbody>");
            foreach (HealthcheckData data in consolidation)
            {
                if (data.GPOLsaPolicy != null)
                {
                    foreach (GPPSecurityPolicy policy in data.GPOLsaPolicy)
                    {
                        foreach (GPPSecurityPolicyProperty property in policy.Properties)
                        {
                            Add(@"
						<TR>
							<TD class='text'>" + PrintDomain(data.Domain) + @"</TD>
							<TD class='text'>" + Encode(policy.GPOName) + @"</TD>
							<TD class='text'>" + GetLinkForLsaSetting(property.Property) + @"</TD>
							<TD class='num'>" + property.Value + @"</TD>
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
				<table class=""table table-striped table-bordered sortable-theme-bootstrap"" data-sortable="""">
					<thead><TR> 
						<Th>Domain</Th>
						<Th>GPO Name</Th>
						<Th>Password origin</Th>
						<Th>UserName</Th>
						<Th>Password</Th>
						<Th>Changed</Th>
						<Th>Other</Th>
						</TR>
					</thead>
					<tbody>
");
            foreach (HealthcheckData data in consolidation)
            {
                foreach (GPPPassword password in data.GPPPassword)
                {
                    Add(@"
						<TR>
							<TD class='text'>" + PrintDomain(data.Domain) + @"</TD>
							<TD class='text'>" + Encode(password.GPOName) + @"</TD>
							<TD class='text'>" + Encode(password.Type) + @"</TD>
							<TD class='text'>" + Encode(password.UserName) + @"</TD>
							<TD class='text'>" + Encode(password.Password) + @"</TD>
							<TD class='text'>" + password.Changed.ToString("u") + @"</TD>
							<TD class='text'>" + Encode(password.Other) + @"</TD>
						</TR>
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
            else if (consolidation.HasDomainAmbigiousName(key))
                return key.ToString();
            return key.DomainName;
        }
    }
}
