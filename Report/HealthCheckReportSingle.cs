//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.template;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace PingCastle.Healthcheck
{
	public class HealthCheckReportSingle : HealthCheckReportBase
    {

        private readonly HealthcheckData HealthCheckData;
        public static int MaxNumberUsersInHtmlReport = 100;
		private readonly ADHealthCheckingLicense _license;
		private readonly Version version;

        public HealthCheckReportSingle(HealthcheckData healthcheckData, ADHealthCheckingLicense license)
        {
            HealthCheckData = healthcheckData;
			version = new Version(HealthCheckData.EngineVersion.Split(' ')[0]);
			_license = license;
        }

		protected override string GenerateTitleInformation()
		{
			return Encode(HealthCheckData.DomainFQDN + " PingCastle " + HealthCheckData.GenerationDate.ToString("yyyy-MM-dd"));
		}


		protected override string GenerateHeaderInformation()
		{
			return GetStyleSheetTheme() + GetStyleSheet();
		}

		public static string GetStyleSheet()
		{
			return @"
<style type=""text/css"">

.modal
{
top: 50px;
}

.modal-header
{
background-color: #FA9C1A;
color: #fff;
}
.ticked { color: #4CAF50;}
.unticked { color: #FF1744;}
.num
{
	text-align: right !important;
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

		protected override string GenerateBodyInformation()
        {
            sb = new StringBuilder();
            Add(@"
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
            Add(HealthCheckData.DomainFQDN);
            Add(@"</a>
                </li>
				<li>
					<a aria-expanded=""false"" role=""button"">");
            Add(HealthCheckData.GenerationDate.ToString("yyyy-MM-dd"));
            Add(@"</a>
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
<div id=""wrapper"" class=""container well"">
	<noscript>
		<div class=""alert alert-warning"">
			<p>PingCastle reports work best with Javascript enabled.</p>
		</div>
	</noscript>
<div class=""row""><div class=""col-lg-12""><h1>");
            Add(HealthCheckData.DomainFQDN);
            Add(@" - Healthcheck analysis</h1>
			<h3>Date: ");
            Add(HealthCheckData.GenerationDate.ToString("yyyy-MM-dd"));
            Add(@" - Engine version: ");
            Add(HealthCheckData.EngineVersion);
            Add(@"</h3>
");
			Add(@"<div class=""alert alert-info"">
This report has been generated with the ");
			Add(String.IsNullOrEmpty(_license.Edition) ? "Basic" : _license.Edition);
			Add(@" Edition of PingCastle.");
			if (String.IsNullOrEmpty(_license.Edition))
			{
				Add(@"
<br><strong>Being part of a commercial package is forbidden</strong> (selling the information contained in the report).<br>
If you are an auditor, you MUST purchase an Auditor license to share the development effort.
");
			}
			Add(@"</div>
");
			Add(@"</div></div>
");
            GenerateContent();
            Add(@"
</div>
");
            return sb.ToString();
        }

		public void GenerateContent()
		{
			GenerateSection("Active Directory Indicators", GenerateIndicators);
			GenerateSection("Domain Information", GenerateDomainInformation);
			GenerateSection("User Information", GenerateUserInformation);
			GenerateSection("Computer Information", GenerateComputerInformation);
			GenerateSection("Admin Groups", GenerateAdminGroupsInformation);
			GenerateSection("Trusts", GenerateTrustInformation);
			GenerateSection("Anomalies", GenerateAnomalyDetail);
			GenerateSection("Password Policies", GeneratePasswordPoliciesDetail);
			GenerateSection("GPO", GenerateGPODetail);
		}

		protected override string GenerateFooterInformation()
		{
			return @"
<script>
   $(function() {
      $(window).scroll(function() {
         if($(window).scrollTop() >= 70) {  
            $('.information-bar').removeClass('hidden');
            $('.information-bar').fadeIn('fast');
         }else{
            $('.information-bar').fadeOut('fast');
         }
      });
   });
$(document).ready(function(){
    $('[data-toggle=""tooltip""]').tooltip({html: true});
});
$(document).ready(function(){
    $('[data-toggle=""popover""]').popover();
});
$(document).ready(function(){
    $('.div_model').on('click', function (e) {
        $('.div_model').not(this).popover('hide');
    });


});
</script>
";
		}

        #region indicators
        private void GenerateIndicators()
        {
            GenerateSubSection("Indicators");
            Add(@"
		<div class=""row"">
			<div class=""col-md-4"">
				<div class=""chart-gauge"">");
            GenerateGauge(HealthCheckData.GlobalScore);
            Add(@"</div>
			</div>
			<div class=""col-md-8"">
					<p class=""lead"">Domain Risk Level: ");
            Add(HealthCheckData.GlobalScore.ToString());
            Add(@" / 100</p>
					<p>It is the maximum score of the 4 indicators and one score cannot be higher than 100. The lower the better</p>
			</div>
		</div>
		<div class=""row"" style=""border: 2px solid #Fa9C1A; margin:2px; padding: 2px;"">
");
            GenerateSubIndicator("Stale Object", HealthCheckData.StaleObjectsScore, HealthcheckRiskRuleCategory.StaleObjects, "It is about operations related to user or computer objects", "DetailStale");
            GenerateSubIndicator("Trusts", HealthCheckData.TrustScore, HealthcheckRiskRuleCategory.Trusts, "It is about links between two Active Directories", "DetailTrusts");
            GenerateSubIndicator("Privileged Accounts", HealthCheckData.PrivilegiedGroupScore, HealthcheckRiskRuleCategory.PrivilegedAccounts, "It is about administrators of the Active Directory", "DetailPrivileged");
            GenerateSubIndicator("Anomalies", HealthCheckData.AnomalyScore, HealthcheckRiskRuleCategory.Anomalies, "It is about specific security control points", "DetailAnomalies");
            Add(@"
		</div>
");
			GenerateRiskModelPanel();
            GenerateIndicatorPanel("DetailStale", "Stale Objects rule details", HealthcheckRiskRuleCategory.StaleObjects);
            GenerateIndicatorPanel("DetailTrusts", "Trusts rule details", HealthcheckRiskRuleCategory.Trusts);
            GenerateIndicatorPanel("DetailPrivileged", "Privileged Accounts rule details", HealthcheckRiskRuleCategory.PrivilegedAccounts);
            GenerateIndicatorPanel("DetailAnomalies", "Anomalies rule details", HealthcheckRiskRuleCategory.Anomalies);
        }

		void GenerateSubIndicator(string category, int score, HealthcheckRiskRuleCategory RiskRuleCategory, string explanation, string reference)
        {
			int numrules = 0;
			if (HealthCheckData.RiskRules != null)
			{
				foreach (var rule in HealthCheckData.RiskRules)
				{
					if (rule.Category == RiskRuleCategory)
						numrules++;
				}
			}
            Add(@"
			<div class=""col-xs-12 col-md-6 col-sm-6"">
				<div class=""row"">
					<div class=""col-md-4 col-xs-8 col-sm-9"">
						<div class=""chart-gauge"">");
            GenerateGauge(score);
            Add(@"</div>
					</div>
					<div class=""col-md-6 col-xs-8 col-sm-9"">
					");
            Add((score == HealthCheckData.GlobalScore ? "<strong>" : ""));
            Add(@"<p>");
            Add(category);
            Add(@" : ");
            Add(score.ToString());
            Add(@" /100</p>");
            Add((score == HealthCheckData.GlobalScore ? "</strong>" : ""));
            Add(@"
					<p class=""small"">");
            Add(Encode(explanation));
            Add(@"</p>
					</div>
					<div class=""col-md-2 col-xs-4 col-sm-3 collapse-group"">
						<p class=""small"">");
            Add(numrules.ToString());
            Add(@" rules matched</p>
					</div>
				</div>
			</div>
");
        }

		int GetRulesNumberForCategory(HealthcheckRiskRuleCategory category)
		{
			int count = 0;
			foreach (var rule in HealthCheckData.RiskRules)
			{
				if (rule.Category == category)
					count++;
			}
			return count;
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
			for (int i = 0;; i++)
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
						List<HealthcheckRiskRule> rulematched = new List<HealthcheckRiskRule>();
						foreach (HealthcheckRiskRule rule in HealthCheckData.RiskRules)
						{
							if (rule.Model == model)
							{
								numrules++;
								score += rule.Points;
								rulematched.Add(rule);
							}
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
						else if (score <= 10)
						{
							tdclass = "model_toimprove";
						}
						else if (score <= 30)
						{
							tdclass = "model_warning";
						}
						else
						{
							tdclass = "model_danger";
						}
						string tooltip = "Rules: " + numrules + " Score: " + score;
						string tooltipdetail = null;
						string modelstring = GetEnumDescription(model);
						rulematched.Sort((HealthcheckRiskRule a, HealthcheckRiskRule b)
							=>
							{
								return a.Points.CompareTo(b.Points);
							});
						foreach (var rule in rulematched)
						{
							tooltipdetail += Encode(rule.Rationale) + "<br>";
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

        void GenerateIndicatorPanel(string id, string title, HealthcheckRiskRuleCategory category)
        {
            Add(@"
		<div class=""row""><div class=""col-lg-12"">
			<a data-toggle=""collapse"" data-target=""#" + id + @""">
				<h2>");
            Add(title);
            Add(@" [");
            Add(GetRulesNumberForCategory(category).ToString());
            Add(@" rules matched]</h2>
			</a>
		</div></div>
		<div class=""row collapse in"" id=""");
            Add(id);
            Add(@"""><div class=""col-lg-12"">
			<div class=""panel-group"" id=""accordion");
            Add(category.ToString());
            Add(@""">
");
            HealthCheckData.RiskRules.Sort((HealthcheckRiskRule a, HealthcheckRiskRule b)
                => 
                {return -a.Points.CompareTo(b.Points);
                }
            );
            foreach (HealthcheckRiskRule rule in HealthCheckData.RiskRules)
            {
                if (rule.Category == category)
                    GenerateIndicatorPanelDetail(category, rule);
            }
            Add(@"
			</div></div>
		</div>");
        }

		string NewLineToBR(string data)
		{
			if (String.IsNullOrEmpty(data))
				return data;
			return data.Replace("\r\n", "<br>\r\n");
		}

        void GenerateIndicatorPanelDetail(HealthcheckRiskRuleCategory category, HealthcheckRiskRule rule)
        {
			string safeRuleId = rule.RiskId.Replace("$", "dollar");
            Add(@"
							<div class=""panel panel-default"">
								<div class=""panel-heading"">
									<a data-toggle=""collapse"" href=""#");
			Add(safeRuleId);
            Add(@""" data-parent=""#accordion");
            Add(category.ToString());
            Add(@""">
										<h4 class=""panel-title"">
											");
            Add(rule.Rationale);
            Add(@"<i class=""pull-right"">+ ");
            Add(rule.Points.ToString());
            Add(@" points</i>
										</h4>
									</a>
								</div>
								<div id=""");
			Add(safeRuleId);
            Add(@""" class=""panel-collapse collapse"">
");
			Add(@"
									<div class=""panel-body"">
");
            var hcrule = HealthcheckRules.GetRuleFromID(rule.RiskId);
            if (hcrule == null)
            {
            }
            else
            {
                Add("<h3>");
                Add(hcrule.Title);
                Add("</h3>\r\n<strong>Description:</strong><p class=\"text-justify\">");
                Add(NewLineToBR(hcrule.Description));
                Add("</p>\r\n<strong>Technical explanation:</strong><p class=\"text-justify\">");
                Add(NewLineToBR(hcrule.TechnicalExplanation));
                Add("</p>\r\n<strong>Advised solution:</strong><p class=\"text-justify\">");
                Add(NewLineToBR(hcrule.Solution));
                Add("</p>\r\n<strong>Points:</strong><p>");
                Add(NewLineToBR(hcrule.GetComputationModelString()));
                Add("</p>\r\n");
                if (!String.IsNullOrEmpty(hcrule.Documentation))
                {
                    Add("<strong>Documentation:</strong><p>");
                    Add(hcrule.Documentation);
                    Add("</p>");
                }
			}
			if (rule.Details != null && rule.Details.Count > 0)
			{
				Add("<strong>Details:</strong><p>");
				Add(String.Join("<br>\r\n", rule.Details.ToArray()));
				Add("</p>");
			}
			Add(@"
									</div>
								</div>
							</div>");
        }

        #endregion indicators

        #region domain info
        private void GenerateDomainInformation()
        {
            Add(@"
		<div class=""row"">
			<div class=""col-md-12 table-responsive"">
				<table class=""table table-striped table-bordered"">
					<thead>
					<tr> 
						<th>Domain</th>
						<th>Netbios Name</th>
						<th>Domain Functional Level</th>
						<th>Forest Functional Level</th>
						<th>Creation date</th>
						<th>DC count</th>
						<th>Schema version</th>
					</tr>
					</thead>
					<tbody>
					<tr>
						<TD class='text'>");
            Add(HealthCheckData.DomainFQDN);
            Add(@"</TD>
						<TD class='text'>");
            Add(HealthCheckData.NetBIOSName);
            Add(@"</TD>
						<TD class='text'>");
            Add(DecodeDomainFunctionalLevel(HealthCheckData.DomainFunctionalLevel));
            Add(@"</TD>
						<TD class='text'>");
            Add(DecodeForestFunctionalLevel(HealthCheckData.ForestFunctionalLevel));
            Add(@"</TD>
						<TD class='text'>");
            Add(HealthCheckData.DomainCreation);
            Add(@"</TD>
						<TD class='num'>");
            Add(HealthCheckData.NumberOfDC);
            Add(@"</TD>
						<TD class='num'>");
            Add(HealthCheckData.SchemaVersion);
            Add(@"</TD>
					</tr>
					</tbody>
					<tfoot></tfoot>
				</table>
			</div>
		</div>
");
        }

        #endregion domain info

        #region user info
        private void GenerateUserInformation()
        {
            Add(@"
		<div class=""row"">
			<div class=""col-md-12 table-responsive"">
				<table class=""table table-striped table-bordered"">
				<thead><TR> 
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
					<TR>
						<TD class='num'>");
            Add(HealthCheckData.UserAccountData.Number);
            Add(@"</TD><TD class='num'>");
            Add(HealthCheckData.UserAccountData.NumberEnabled);
            Add(@"</TD><TD class='num'>");
            Add(HealthCheckData.UserAccountData.NumberDisabled);
            Add(@"</TD><TD class='num'>");
            Add(HealthCheckData.UserAccountData.NumberActive);
            Add(@"</TD><TD class='num'>");
            SectionList("usersaccordion", "sectioninactiveuser", HealthCheckData.UserAccountData.NumberInactive, HealthCheckData.UserAccountData.ListInactive);
            Add(@"</TD><TD class='num'>");
            SectionList("usersaccordion", "sectionlockeduser", HealthCheckData.UserAccountData.NumberLocked, HealthCheckData.UserAccountData.ListLocked);
            Add(@"</TD><TD class='num'>");
            SectionList("usersaccordion", "sectionneverexpiresuser", HealthCheckData.UserAccountData.NumberPwdNeverExpires, HealthCheckData.UserAccountData.ListPwdNeverExpires);
            Add(@"</TD><TD class='num'>");
            SectionList("usersaccordion", "sectionsidhistoryuser", HealthCheckData.UserAccountData.NumberSidHistory, HealthCheckData.UserAccountData.ListSidHistory);
            Add(@"</TD><TD class='num'>");
            SectionList("usersaccordion", "sectionbadprimarygroupuser", HealthCheckData.UserAccountData.NumberBadPrimaryGroup, HealthCheckData.UserAccountData.ListBadPrimaryGroup);
            Add(@"</TD><TD class='num'>");
            SectionList("usersaccordion", "sectionpwdnotrequireduser", HealthCheckData.UserAccountData.NumberPwdNotRequired, HealthCheckData.UserAccountData.ListPwdNotRequired);
            Add(@"</TD><TD class='num'>");
            SectionList("usersaccordion", "sectiondesenableduser", HealthCheckData.UserAccountData.NumberDesEnabled, HealthCheckData.UserAccountData.ListDesEnabled);
            Add(@"</TD><TD class='num'>");
            SectionList("usersaccordion", "sectiontrusteddelegationuser", HealthCheckData.UserAccountData.NumberTrustedToAuthenticateForDelegation, HealthCheckData.UserAccountData.ListTrustedToAuthenticateForDelegation);
            Add(@"</TD><TD class='num'>");
            SectionList("usersaccordion", "sectionreversiblenuser", HealthCheckData.UserAccountData.NumberReversibleEncryption, HealthCheckData.UserAccountData.ListReversibleEncryption);
            Add(@"</TD>
                    </TR>
				</tbody>
				</table>
			</div>
		</div>
");
			GenerateListAccount(HealthCheckData.UserAccountData, "user", "usersaccordion");
			GenerateDomainSIDHistoryList(HealthCheckData.UserAccountData);
        }

		private void GenerateListAccount(HealthcheckAccountData data, string root, string accordion)
		{
			GenerateAccordion(accordion, 
                () =>
                {
                    if (data.ListInactive != null && data.ListInactive.Count > 0)
                    {
                        GenerateListAccountDetail(accordion, "sectioninactive" + root, "Inactive objects (Last usage > 6 months) ", data.ListInactive);
                    }
                    if (data.ListLocked != null && data.ListLocked.Count > 0)
                    {
                        GenerateListAccountDetail(accordion, "sectionlocked" + root, "Locked objects ", data.ListLocked);
                    }
                    if (data.ListPwdNeverExpires != null && data.ListPwdNeverExpires.Count > 0)
                    {
                        GenerateListAccountDetail(accordion, "sectionneverexpires" + root, "Objects with a password which never expires ", data.ListPwdNeverExpires);
                    }
                    if (data.ListSidHistory != null && data.ListSidHistory.Count > 0)
                    {
                        GenerateListAccountDetail(accordion, "sectionsidhistory" + root, "Objects having the SIDHistory populated ", data.ListSidHistory);
                    }
                    if (data.ListBadPrimaryGroup != null && data.ListBadPrimaryGroup.Count > 0)
                    {
                        GenerateListAccountDetail(accordion, "sectionbadprimarygroup" + root, "Objects having the primary group attribute changed ", data.ListBadPrimaryGroup);
                    }
                    if (data.ListPwdNotRequired != null && data.ListPwdNotRequired.Count > 0)
                    {
                        GenerateListAccountDetail(accordion, "sectionpwdnotrequired" + root, "Objects which can have an empty password ", data.ListPwdNotRequired);
                    }
                    if (data.ListDesEnabled != null && data.ListDesEnabled.Count > 0)
                    {
                        GenerateListAccountDetail(accordion, "sectiondesenabled" + root, "Objects which can use DES in kerberos authentication ", data.ListDesEnabled);
                    }
                    if (data.ListTrustedToAuthenticateForDelegation != null && data.ListTrustedToAuthenticateForDelegation.Count > 0)
                    {
                        GenerateListAccountDetail(accordion, "sectiontrusteddelegation" + root, "Objects trusted to authenticate for delegation ", data.ListTrustedToAuthenticateForDelegation);
                    }
                    if (data.ListTrustedToAuthenticateForDelegation != null && data.ListTrustedToAuthenticateForDelegation.Count > 0)
                    {
                        GenerateListAccountDetail(accordion, "sectionreversible" + root, "Objects having a reversible password ", data.ListReversibleEncryption);
                    }
                    if (data.ListDuplicate != null && data.ListDuplicate.Count > 0)
                    {
                        GenerateListAccountDetail(accordion, "sectionduplicate" + root, "Objects being duplicates ", data.ListDuplicate);
                    }
                    if (data.ListNoPreAuth != null && data.ListNoPreAuth.Count > 0)
                    {
                        GenerateListAccountDetail(accordion, "sectionnopreauth" + root, "Objects without kerberos preauthentication ", data.ListNoPreAuth);
                    }
                });
		}

		void SectionList(string accordion, string section, int value, List<HealthcheckAccountDetailData> list)
		{
            if (value > 0 && list != null && list.Count > 0)
            {
                Add(@"<a data-toggle=""collapse"" href=""#");
                Add(section);
                Add(@""" data-parent=""#");
                Add(accordion);
                Add(@""">");
                Add(value);
                Add(@"</a>");
            }
            else
            {
                Add(value);
            }
		}

		void GenerateListAccountDetail(string accordion, string id, string title, List<HealthcheckAccountDetailData> list)
		{
			if (list == null)
			{
				return;
			}
            Add(@"
					<div class=""panel panel-default"">
						<div class=""panel-heading"">
							<a data-toggle=""collapse"" href=""#" + id + @""" data-parent=""#" + accordion + @""">
								<h4 class=""panel-title"">
									");
            Add(title);
            Add(@"<i class=""pull-right"">[");
            Add(list.Count);
            Add(@"]</i>
								</h4>
							</a> 
						</div>
						<div id=""");
            Add(id);
            Add(@""" class=""panel-collapse collapse"">
							<div class=""panel-body"">
								<div class=""col-md-12 table-responsive"">
									<table class=""table table-striped table-bordered sortable-theme-bootstrap"" data-sortable="""">
									<thead>
									<tr> 
										<th>Name</th>
										<th>Creation</th>
										<th>Last logon</th>
										<th>Distinguished name</th>
									</tr>
									</thead>
									<tbody>");
			int number = 0;
			list.Sort((HealthcheckAccountDetailData a, HealthcheckAccountDetailData b)
				=> 
				{
					return String.Compare(a.Name, b.Name);
				}
				);
			foreach (HealthcheckAccountDetailData detail in list)
			{
                Add(@"
										<TR><TD class='text'>");
                Add(Encode(detail.Name));
                Add(@"</TD>
											<TD class='text'>");
                Add((detail.CreationDate > DateTime.MinValue ? detail.CreationDate.ToString("u") : "Access Denied"));
                Add(@"</TD>
											<TD class='text'>");
                Add((detail.LastLogonDate > DateTime.MinValue ? detail.LastLogonDate.ToString("u") : "Never"));
                Add(@"</TD>
											<TD class='text'>");
                Add(Encode(detail.DistinguishedName));
                Add(@"</TD>
										</TR>");
				number++;
				if (number >= MaxNumberUsersInHtmlReport)
				{
                    Add("<TR><TD class='text'>Output limited to ");
                    Add(MaxNumberUsersInHtmlReport);
                    Add(" items - add \"--no-enum-limit\" to remove that limit</td></tr>");
					break;
				}
			}
			Add(@"
									</tbody>
									</table>
								</div>
							</div>
						</div>
					</div>");
		}

		private void GenerateDomainSIDHistoryList(HealthcheckAccountData data)
		{
			if (data.ListDomainSidHistory == null || data.ListDomainSidHistory.Count == 0)
				return;

            GenerateSubSection("SID History");
            Add(@"
		<div class=""row"">
			<div class=""col-md-12 table-responsive"">
				<table class=""table table-striped table-bordered sortable-theme-bootstrap"" data-sortable="""">
				<thead><TR> 
					<Th>SID History from domain</Th>
					<Th>First date seen</Th>
					<Th>Last date seen</Th>
					<Th>Count</Th>
				</TR></thead>
				<tbody>");
			data.ListDomainSidHistory.Sort(
				(HealthcheckSIDHistoryData x, HealthcheckSIDHistoryData y) =>
				{
					return String.Compare(x.FriendlyName, y.FriendlyName);
				}
				);
			foreach (HealthcheckSIDHistoryData domainSidHistory in data.ListDomainSidHistory)
			{
                Add("<TR><TD class='text'>");
                Add(Encode(domainSidHistory.FriendlyName));
                Add("</TD><TD class='text'>");
                Add(domainSidHistory.FirstDate);
                Add("</TD><TD class='text'>");
                Add(domainSidHistory.LastDate);
                Add("</TD><TD class='num'>");
                Add(domainSidHistory.Count);
                Add("</TD></TR>");
			}
			Add(@"
				</tbody></table>
			</div>
		</div>");
		}

        #endregion user info
		#region computer info
		private void GenerateComputerInformation()
		{
            Add(@"
		<div class=""row"">
			<div class=""col-md-12 table-responsive"">
				<table class=""table table-striped table-bordered"">
				<thead><TR> 
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
					<TR>
						<TD class='num'>");
            Add(HealthCheckData.ComputerAccountData.Number);
            Add(@"</TD>
						<TD class='num'>");
            Add(HealthCheckData.ComputerAccountData.NumberEnabled);
            Add(@"</TD>
						<TD class='num'>");
            Add(HealthCheckData.ComputerAccountData.NumberDisabled);
            Add(@"</TD>
						<TD class='num'>");
            Add(HealthCheckData.ComputerAccountData.NumberActive);
            Add(@"</TD>
						<TD class='num'>");
            SectionList("computersaccordion", "sectioninactivecomputer", HealthCheckData.ComputerAccountData.NumberInactive, HealthCheckData.ComputerAccountData.ListInactive);
            Add(@"</TD><TD class='num'>");
            SectionList("computersaccordion", "sectionsidhistorycomputer", HealthCheckData.ComputerAccountData.NumberSidHistory, HealthCheckData.ComputerAccountData.ListSidHistory);
            Add(@"</TD><TD class='num'>");
            SectionList("computersaccordion", "sectionbadprimarygroupcomputer", HealthCheckData.ComputerAccountData.NumberBadPrimaryGroup, HealthCheckData.ComputerAccountData.ListBadPrimaryGroup);
            Add(@"</TD><TD class='num'>");
            SectionList("computersaccordion", "sectiontrusteddelegationcomputer", HealthCheckData.ComputerAccountData.NumberTrustedToAuthenticateForDelegation, HealthCheckData.ComputerAccountData.ListTrustedToAuthenticateForDelegation);
            Add(@"</TD><TD class='num'>");
            SectionList("computersaccordion", "sectionreversiblencomputer", HealthCheckData.ComputerAccountData.NumberReversibleEncryption, HealthCheckData.ComputerAccountData.ListReversibleEncryption);
            Add(@"</TD></TR>
				</tbody>
				</table>
			</div>
		</div>
");
			GenerateListAccount(HealthCheckData.ComputerAccountData, "computer", "computersaccordion");
			GenerateOperatingSystemList();
			GenerateDomainSIDHistoryList(HealthCheckData.ComputerAccountData);
			GenerateDCInformation();
		}

		private void GenerateOperatingSystemList()
		{
            GenerateSubSection("Operating Systems");
			bool oldOS = version <= new Version(2, 5, 0, 0);
			if (oldOS)
			{
				Add(@"
			<div class=""row"">
				<div class=""col-md-12 table-responsive"">
					<table class=""table table-striped table-bordered sortable-theme-bootstrap"" data-sortable="""">
					<thead><TR> 
						<Th>Operating System</Th>
						<Th>Count</Th>
					</TR></thead>
					<tbody>");
				HealthCheckData.OperatingSystem.Sort(
					(HealthcheckOSData x, HealthcheckOSData y) =>
					{
						return OrderOS(x.OperatingSystem, y.OperatingSystem);
					}
					);
				{
					foreach (HealthcheckOSData os in HealthCheckData.OperatingSystem)
					{
						Add("<TR><TD class='text'>");
						Add(Encode(os.OperatingSystem));
						Add("</TD><TD class='num'>");
						Add(os.NumberOfOccurence);
						Add("</TD></TR>");
					}
				}
				Add(@"
					</tbody></table>
				</div>
			</div>");
			}
			else
			{
				Add(@"
			<div class=""row"">
				<div class=""col-md-12 table-responsive"">
					<table class=""table table-striped table-bordered sortable-theme-bootstrap"" data-sortable="""">
					<thead><TR> 
						<Th>Operating System</Th>
						<Th>Nb OS</Th>
						<Th>Nb Enabled</Th>
						<Th>Nb Disabled</Th>
						<Th>Nb Active</Th>
						<Th>Nb Inactive</Th>
						<Th>Nb SidHistory</Th>
						<Th>Nb Bad PrimaryGroup</Th>
						<Th>Nb Trusted delegation</Th>
						<Th>Nb Reversible password</Th>
					</TR></thead>
					<tbody>");
				HealthCheckData.OperatingSystem.Sort(
					(HealthcheckOSData x, HealthcheckOSData y) =>
					{
						return OrderOS(x.OperatingSystem, y.OperatingSystem);
					}
					);
				{
					foreach (HealthcheckOSData os in HealthCheckData.OperatingSystem)
					{
						Add(@"<TR>
						<TD>");
						Add(os.OperatingSystem);
						Add(@"</TD>
									<TD class='num'>");
						Add(os.data.Number);
						Add(@"</TD>
									<TD class='num'>");
						Add(os.data.NumberEnabled);
						Add(@"</TD>
									<TD class='num'>");
						Add(os.data.NumberDisabled);
						Add(@"</TD>
									<TD class='num'>");
						Add(os.data.NumberActive);
						Add(@"</TD>
									<TD class='num'>");
						Add(os.data.NumberInactive);
						Add(@"</TD><TD class='num'>");
						Add(os.data.NumberSidHistory);
						Add(@"</TD><TD class='num'>");
						Add(os.data.NumberBadPrimaryGroup);
						Add(@"</TD><TD class='num'>");
						Add(os.data.NumberTrustedToAuthenticateForDelegation);
						Add(@"</TD><TD class='num'>");
						Add(os.data.NumberReversibleEncryption);
						Add(@"</TD></TR>");
					}
				}
				Add(@"
					</tbody></table>
				</div>
			</div>");
			}
		}

		private void GenerateDCInformation()
		{
			if (HealthCheckData.DomainControllers == null || HealthCheckData.DomainControllers.Count == 0)
				return;

            GenerateSubSection("Domain controllers");
            Add(@"
					<div class=""panel panel-default"">
						<div class=""panel-heading"">
							<a data-toggle=""collapse"" href=""#compterDC"">
								<h4 class=""panel-title"">
									Domain controllers<i class=""pull-right"">[");
            Add(HealthCheckData.DomainControllers.Count);
            Add(@"]</i>
								</h4>
							</a>
						</div>
						<div id=""compterDC"" class=""panel-collapse collapse"">
							<div class=""panel-body"">
								<div class=""col-md-12 table-responsive"">
									<table class=""table table-striped table-bordered sortable-theme-bootstrap"" data-sortable="""">
									<thead>
									<tr> 
										<th>Domain controller</th>
										<th>OS</th>
										<th>Creation Date</th>
										<th>Startup Time</th>
										<th>Uptime</th>
										<th>Owner</th>
										<th>Null sessions</th>
										<th>SMB v1</th>
									</tr>
									</thead>
									<tbody>");

            int count = 0;
			foreach (var dc in HealthCheckData.DomainControllers)
			{
				count++;
                Add(@"
<TR><TD class='text'>");
                Add(Encode(dc.DCName));
                Add(@"</TD>
<TD class='text'>");
                Add(Encode(dc.OperatingSystem));
                Add(@"</TD>
<TD class='text'>");
                Add((dc.CreationDate == DateTime.MinValue ? "Unknown" : dc.CreationDate.ToString("u")));
                Add(@"</TD>
<TD class='text'>");
                Add((dc.StartupTime == DateTime.MinValue ? (dc.LastComputerLogonDate.AddDays(60) < DateTime.Now ? "Inactive?" : "Unknown") : (dc.StartupTime.AddMonths(6) < DateTime.Now ? "<span class='unticked'>" + dc.StartupTime.ToString("u") + "</span>" : dc.StartupTime.ToString("u"))));
                Add(@"</TD>
<TD class='text'>");
                Add((dc.StartupTime == DateTime.MinValue ? "" : (DateTime.Now.Subtract(dc.StartupTime)).Days + " days"));
                Add(@"</TD>
<TD class='text'>");
                Add((String.IsNullOrEmpty(dc.OwnerName) ? dc.OwnerSID : dc.OwnerName));
                Add(@"</TD>
<TD class='text'>");
                Add((dc.HasNullSession ? "<span class='unticked'>YES</span>" : "<span class='ticked'>NO</span>"));
                Add(@"</TD>
<TD class='text'>");
                Add((dc.SupportSMB1 ? "<span class='unticked'>YES</span>" : "<span class='ticked'>NO</span>"));
                Add(@"</TD></tr>
");
			}
			Add( @"
									</tbody>
									</table>
								</div>
							</div>
						</div>
					</div>
");
		}

		
		#endregion computer info

		#region admin groups
		private void GenerateAdminGroupsInformation()
		{
			if (HealthCheckData.PrivilegedGroups != null)
			{
				Add(@"
		<div class=""row"">
			<div class=""col-md-12 table-responsive"">
				<table class=""table table-striped table-bordered sortable-theme-bootstrap"" data-sortable="""">
				<thead><TR> 
					<Th>Group Name</Th>
					<Th>Nb Admins</Th>
					<Th>Nb Enabled</Th>
					<Th>Nb Disabled</Th>
					<Th>Nb Inactive</Th>
					<Th>Nb PWd never expire</Th>
");
				if (version > new Version(2, 5, 2))
				{
					Add(@"<Th>Nb Smart Card required</Th>");
				}
				Add(@"
					<Th>Nb can be delegated</Th>
					<Th>Nb external users</Th>
				</TR>
				</thead>
				<tbody>
");
				HealthCheckData.PrivilegedGroups.Sort((HealthCheckGroupData a, HealthCheckGroupData b)
					=>
					{
						return String.Compare(a.GroupName, b.GroupName);
					}
				);
				foreach (HealthCheckGroupData group in HealthCheckData.PrivilegedGroups)
				{
                    Add(@"
				<TR>
					<TD class='text'>");
                    Add((group.Members != null && group.Members.Count > 0 ? @"<a data-toggle=""modal"" href=""#" + GenerateModalAdminGroupIdFromGroupName(group.GroupName) + @""">" + Encode(group.GroupName) + "</a>" : Encode(group.GroupName)));
                    Add(@"</TD>
					<TD class='text'>");
                    Add(group.NumberOfMember);
                    Add(@"</TD>
					<TD class='text'>");
                    Add(group.NumberOfMemberEnabled);
                    Add(@"</TD>
					<TD class='text'>");
                    Add(group.NumberOfMemberDisabled);
                    Add(@"</TD>
					<TD class='text'>");
                    Add(group.NumberOfMemberInactive);
                    Add(@"</TD>
					<TD class='text'>");
                    Add(group.NumberOfMemberPwdNeverExpires);
					if (version > new Version(2, 5, 2))
					{
						Add(@"</TD>
					<TD class='text'>");
						Add(group.NumberOfSmartCardRequired);
					}
                    Add(@"</TD>
					<TD class='text'>");
                    Add(group.NumberOfMemberCanBeDelegated);
                    Add(@"</TD>
					<TD class='text'>");
                    Add(group.NumberOfExternalMember);
                    Add(@"</TD>
				</TR>
	");
				}
            Add(@"
				</tbody>
				</table>
			</div>
		</div>
");
				foreach (HealthCheckGroupData group in HealthCheckData.PrivilegedGroups)
				{
					if (group.Members != null && group.Members.Count > 0)
					{
						GenerateModalAdminGroup(GenerateModalAdminGroupIdFromGroupName(group.GroupName), group.GroupName,
									() => GenerateAdminGroupsDetail(group.Members));
					}
				}
            }
			
            if (HealthCheckData.AllPrivilegedMembers != null && HealthCheckData.AllPrivilegedMembers.Count > 0)
            {
                GenerateAccordion("admingroups",
                    () =>
                    {
                    Add(@"
					<div class=""panel panel-default"">
						<div class=""panel-heading"">
							<a data-toggle=""collapse"" href=""#allprivileged"" data-parent=""#admingroups"">
								<h4 class=""panel-title"">
									All users in Admins groups <i class=""pull-right"">[");
                    Add(+HealthCheckData.AllPrivilegedMembers.Count);
                    Add(@"]</i>
								</h4>
							</a>
						</div>
						<div id=""allprivileged"" class=""panel-collapse collapse"">
							<div class=""panel-body"">
								<div class=""col-md-12 table-responsive"">
");
                        GenerateAdminGroupsDetail(HealthCheckData.AllPrivilegedMembers);
                        Add(@"
								</div>
							</div>
						</div>
					</div>
");
                    });
            }

            if (HealthCheckData.Delegations != null && HealthCheckData.Delegations.Count > 0)
            {
                Add(@"
					<div class=""panel panel-default"">
						<div class=""panel-heading"">
							<a data-toggle=""collapse"" href=""#alldelegation"" data-parent=""#admingroups"">
								<h4 class=""panel-title"">
									All delegations <i class=""pull-right"">[");
                Add(HealthCheckData.Delegations.Count);
                Add(@"]</i>
								</h4>
							</a>
						</div>
						<div id=""alldelegation"" class=""panel-collapse collapse"">
							<div class=""panel-body"">
								<div class=""col-md-12 table-responsive"">
");
                GenerateDelegationDetail();
                Add(@"
								</div>
							</div>
						</div>
					</div>
");
            }
		}
		private string GenerateModalAdminGroupIdFromGroupName(string groupname)
		{
			return "modal" + groupname.Replace(" ", "-").Replace("<","");
		}
		private void GenerateModalAdminGroup(string id, string title, GenerateContentDelegate content)
		{
            Add(@"
			<!-- Modal ");
            Add(id);
            Add(@"-->
			<div class=""modal fade"" id=""" + id + @""" role=""dialog"">
				<div class=""modal-dialog modal-lg"">
				<!-- Modal content-->
					<div class=""modal-content"">
						<div class=""modal-header"">
							<button type=""button"" class=""close"" data-dismiss=""modal"">&times;</button>
							<span class=""modal-title"">" + title + @"</span>
						</div>
						<div class=""modal-body"">
							<div class=""row table-responsive"">
");
            content();
            Add(@"
							</div>
						</div>
						<div class=""modal-footer"">
							<button type=""button"" class=""btn btn-default"" data-dismiss=""modal"">Close</button>
						</div>
					</div>
				</div>
			</div>
			<!-- Modal ");
            Add(id);
            Add(@" end -->
");
		}

		private void GenerateDelegationDetail()
		{
			Add(@"<table class=""table table-striped table-bordered sortable-theme-bootstrap"" data-sortable="""">
<thead><TR> 
<Th>DistinguishedName</Th>
<Th>Account</Th>
<Th>Right</Th>
</TR>
</thead>
<tbody>
");
			HealthCheckData.Delegations.Sort(OrderDelegationData);

			foreach (HealthcheckDelegationData delegation in HealthCheckData.Delegations)
			{
				int dcPathPos = delegation.DistinguishedName.IndexOf(",DC=");
				string path = delegation.DistinguishedName;
				if (dcPathPos > 0)
					path = delegation.DistinguishedName.Substring(0, dcPathPos);
                Add(@"<TR>
<TD class='text'>");
                Add(Encode(path));
                Add(@"</TD>
<TD class='text'>");
                Add(Encode(delegation.Account));
                Add(@"</TD>
<TD class='text'>");
                Add(Encode(delegation.Right));
                Add(@"</TD>
</TR>
");
			}
			Add(@"</tbody>
</table>
<br>");
		}

		private void GenerateAdminGroupsDetail(List<HealthCheckGroupMemberData> members)
		{
			if (members != null)
			{
				Add(@"
<table class=""table table-striped table-bordered sortable-theme-bootstrap"" data-sortable="""">
<thead><TR> 
	<Th>SamAccountName</Th>
	<Th>Enabled</Th>
	<Th>Active</Th>
	<Th>Pwd never Expired</Th>
	<Th>Locked</Th>
");
				if (version > new Version(2, 5, 2))
				{
					Add(@"<Th>Smart Card required</Th>");
				}
				Add(@"<Th>Flag Cannot be delegated present</Th>
	<Th>Distinguished name</Th>
</TR>
</thead>
<tbody>
");
				members.Sort((HealthCheckGroupMemberData a,HealthCheckGroupMemberData b)
					=>
						{
							return String.Compare(a.Name, b.Name);
						}
				);
				foreach (HealthCheckGroupMemberData member in members)
				{
					if (member.IsExternal)
					{
                        Add(@"<TR>
	<TD class='text'>");
                        Add(Encode(member.Name));
                        Add(@"</TD>
	<TD class='text'>External</TD>
	<TD class='text'>External</TD>
	<TD class='text'>External</TD>
	<TD class='text'>External</TD>
	<TD class='text'>External</TD>
	<TD class='text'>");
						if (version > new Version(2, 5, 2))
						{
							Add(@"External</TD>
	<TD class='text'>");
						}
                        Add(Encode(member.DistinguishedName));
                        Add(@"</TD>
</TR>
");
					}
					else
					{
                        Add(@"<TR>
	<TD class='text'>");
                        Add(Encode(member.Name));
                        Add(@"</TD>
	<TD class='text'>");
                        Add((member.IsEnabled ? "<span class='ticked'>&#10003;</span>" : "<span class='unticked'>&#10007;</span>"));
                        Add(@"</TD>
	<TD class='text'>");
                        Add((member.IsActive ? "<span class='ticked'>&#10003;</span>" : "<span class='unticked'>&#10007;</span>"));
                        Add(@"</TD>
	<TD class='text'>");
                        Add((member.DoesPwdNeverExpires ? "<span class='unticked'>YES</span>" : "<span class='ticked'>NO</span>"));
                        Add(@"</TD>
	<TD class='text'>");
                        Add((member.IsLocked ? "<span class='unticked'>YES</span>" : "<span class='ticked'>NO</span>"));
                        Add(@"</TD>
	<TD class='text'>");
						if (version > new Version(2, 5, 2))
						{
							Add((member.SmartCardRequired ? "<span class='ticked'>YES</span>" : "<span>NO</span>"));
							Add(@"</TD>
	<TD class='text'>");
						}
                        Add((!member.CanBeDelegated ? "<span class='ticked'>YES</span>" : "<span class='unticked'>NO</span>"));
                        Add(@"</TD>
	<TD class='text'>");
                        Add(Encode(member.DistinguishedName));
                        Add(@"</TD>
</TR>
");
					}
				}
				Add(@"</tbody>
</table>
");
			}
		}

		// revert an OU string order to get a string orderable
		// ex: OU=myOU,DC=DC   => DC=DC,OU=myOU
		private string GetDelegationSortKey(HealthcheckDelegationData a)
		{
			string[] apart = a.DistinguishedName.Split(',');
			string[] apart1 = new string[apart.Length];
			for (int i = 0; i < apart.Length; i++)
			{
				apart1[i] = apart[apart.Length - 1 - i];
			}
			return String.Join(",", apart1);
		}
		private int OrderDelegationData(HealthcheckDelegationData a, HealthcheckDelegationData b)
		{
			if (a.DistinguishedName == b.DistinguishedName)
				return String.Compare(a.Account, b.Account);
			return String.Compare(GetDelegationSortKey(a), GetDelegationSortKey(b));
		}

        #endregion admin groups

        #region trust
        void GenerateTrustInformation()
		{
			List<string> knowndomains = new List<string>();
            GenerateSubSection("Discovered Domains");
            Add(@"
		<div class=""row"">
			<div class=""col-md-12 table-responsive"">
				<table class=""table table-striped table-bordered sortable-theme-bootstrap"" data-sortable="""">
					<thead><TR>
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
			foreach (HealthCheckTrustData trust in HealthCheckData.Trusts)
			{
				string sid = (string.IsNullOrEmpty(trust.SID) ? "[Unknown]" : trust.SID);
				string netbios = (string.IsNullOrEmpty(trust.NetBiosName) ? "[Unknown]" : trust.NetBiosName);
				string sidfiltering = TrustAnalyzer.GetSIDFiltering(trust);
				if (sidfiltering == "Yes")
				{
					sidfiltering = "<span class=\"ticked\">" + sidfiltering + "</span>";
				}
				else if (sidfiltering == "No")
				{
					sidfiltering = "<span class=\"unticked\">"+ sidfiltering + "</span>";
				}
                Add(@"<TR>
<TD class='text'>");
                if (GetUrlCallback == null)
                {
                    Add(@"<a href=""#"" data-toggle=""tooltip"" data-placement=""auto right"" title=""SID:");
                    Add(sid);
                    Add(@"<br>Netbios: ");
                    Add(netbios);
                    Add(@""">");
                    Add(Encode(trust.TrustPartner));
                    Add(@"</a>");
                }
                else
                {
                    Add(GetUrlCallback(trust.Domain, trust.TrustPartner));
                }
                Add(@"</TD>
<TD class='text'>");
                Add(TrustAnalyzer.GetTrustType(trust.TrustType));
                Add(@"</TD>
<TD class='text'>");
                Add(TrustAnalyzer.GetTrustAttribute(trust.TrustAttributes));
                Add(@"</TD>
<TD class='text'>");
                Add(TrustAnalyzer.GetTrustDirection(trust.TrustDirection));
                Add(@"</TD>
<TD class='text'>");
                Add(sidfiltering);
                Add(@"</TD>
<TD class='text'>");
                Add(trust.CreationDate);
                Add(@"</TD>
<TD class='text'>");
                Add((trust.IsActive ? trust.IsActive.ToString() : "<span class=\"unticked\">False</span>"));
                Add(@"</TD>
</TR>
");
			}
			Add(@"
					</tbody>
				</table>
			</div>
		</div>
");

            GenerateSubSection("Reachable Domains");

            Add(@"
		<div class=""row"">
			<div class=""col-md-12 table-responsive"">
				<table class=""table table-striped table-bordered sortable-theme-bootstrap"" data-sortable="""">
					<thead><TR> 
						<Th>Reachable domain</Th>
						<Th>Via</Th>
						<Th>Netbios</Th>
						<Th>Creation date</Th>
						</TR>
					</thead>
					<tbody>
");
			foreach (HealthCheckTrustData trust in HealthCheckData.Trusts)
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
                    Add(@"<TR>
<TD class='text'>");
                    if (GetUrlCallback == null)
                    {
                        Add(Encode(di.DnsName));
                    }
                    else
                    {
                        Add(GetUrlCallback(di.Domain, di.DnsName));
                    }
                Add(@"</TD>
<TD class='text'>");
                    if (GetUrlCallback == null)
                    {
                        Add(Encode(trust.TrustPartner));
                    }
                    else
                    {
                        Add(GetUrlCallback(trust.Domain, trust.TrustPartner));
                    }
                Add(@"</TD>
<TD class='text'>");
                    Add(Encode(di.NetbiosName));
                    Add(@"</TD>
<TD class='text'>");
                    Add(di.CreationDate);
                    Add(@"</TD>
</TR>
");
				}
			}
			if (HealthCheckData.ReachableDomains != null)
			{
				foreach (HealthCheckTrustDomainInfoData di in HealthCheckData.ReachableDomains)
				{
                    Add(@"<TR>
<TD class='text'>");
                    if (GetUrlCallback == null)
                    {
                        Add(Encode(di.DnsName));
                    }
                    else
                    {
                        Add(GetUrlCallback(di.Domain, di.DnsName));
                    }
                    Add(@"</TD>
<TD class='text'>Unknown</TD>
<TD class='text'>");
                    Add(Encode(di.NetbiosName));
                    Add(@"</TD>
<TD class='text'>Unknown</TD>
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
		#endregion trust

		#region anomaly
		private void GenerateAnomalyDetail()
		{
            GenerateSubSection("Backup");
            Add(@"
		<div class=""row""><div class=""col-lg-12"">
<p>The program checks the last date of the AD backup. This date is computed using the replication metadata of the attribute dsaSignature (<a href=""https://technet.microsoft.com/en-us/library/jj130668(v=ws.10).aspx"">reference</a>).</p>
<p><strong>Last backup date: </strong> " + (HealthCheckData.LastADBackup == DateTime.MaxValue ? "<span class=\"unticked\">Never</span>" : (HealthCheckData.LastADBackup == DateTime.MinValue ? "<span class=\"unticked\">Not checked (older version of PingCastle)</span>" : HealthCheckData.LastADBackup.ToString("u"))) + @"</p>
		</div></div>
");

            GenerateSubSection("LAPS");
            Add(@"
		<div class=""row""><div class=""col-lg-12"">
<p><a href=""https://support.microsoft.com/en-us/kb/3062591"">LAPS</a> is used to have a unique local administrator password on all workstations / servers of the domain.
Then this password is changed at a fixed interval. The risk is when a local administrator hash is retrieved and used on other workstation in a pass-the-hash attack.</p>
<p>Mitigation: having a process when a new workstation is created or install LAPS and apply it through a GPO</p>
<p><strong>LAPS installation date: </strong> " + (HealthCheckData.LAPSInstalled == DateTime.MaxValue ? "<span class=\"unticked\">Never</span>" : (HealthCheckData.LAPSInstalled == DateTime.MinValue ? "<span class=\"unticked\">Not checked (older version of PingCastle)</span>" : HealthCheckData.LAPSInstalled.ToString("u"))) + @"</p>
		</div></div>
");
            GenerateSubSection("Windows Event Forwarding (WEF)");
            Add(@"
		<div class=""row""><div class=""col-lg-12"">
<p>Windows Event Forwarding is a native mechanism used to collect logs on all workstations / servers of the domain.
Microsoft recommends to <a href=""https://docs.microsoft.com/en-us/windows/threat-protection/use-windows-event-forwarding-to-assist-in-instrusion-detection"">Use Windows Event Forwarding to help with intrusion detection</a>
Here is the list of servers configure for WEF found in GPO</p>
<p><strong>Number of WEF servers configured: </strong> " + (HealthCheckData.GPOEventForwarding.Count) + @"</p>
		</div></div>
");
			// wef
			if (HealthCheckData.GPOEventForwarding.Count > 0)
			{
				Add(@"
		<div class=""row"">
			<div class=""col-md-12"">
				<div class=""panel-group"" id=""wef"">
					<div class=""panel panel-default"">
						<div class=""panel-heading"">
							<a data-toggle=""collapse"" href=""#wefPanel"" data-parent=""#wef"">
								<h4 class=""panel-title"">
									Windows Event Forwarding servers <i class=""pull-right"">[" + HealthCheckData.GPOEventForwarding.Count + @"]</i>
								</h4>
							</a>
						</div>
						<div id=""wefPanel"" class=""panel-collapse collapse"">
							<div class=""panel-body"">
								<div class=""col-md-12 table-responsive"">
									<TABLE class=""table table-striped table-bordered sortable-theme-bootstrap"" data-sortable="""">
										<thead><TR> 
											<Th>GPO Name</Th>
											<Th>Order</Th>
											<Th>Server</Th>
											</TR>
										</thead>
										<tbody>
");
				// descending sort
				HealthCheckData.GPOEventForwarding.Sort(
					(GPOEventForwardingInfo a, GPOEventForwardingInfo b)
						=>
					{
						int comp = String.Compare(a.GPOName, b.GPOName);
						if (comp == 0)
							comp = (a.Order > b.Order ? 1 : (a.Order == b.Order ? 0 : -1));
						return comp;
					}
					);

				foreach (var info in HealthCheckData.GPOEventForwarding)
				{
                    Add(@"
<TR>
<TD class='text'>");
                    Add(Encode(info.GPOName));
                    Add(@"</TD>
<TD class='num'>");
                    Add(info.Order);
                    Add(@"</TD>
<TD class='text'>");
                    Add(Encode(info.Server));
                    Add(@"</TD>
</TR>
");
				}
				Add(@"
									</tbody></table>
								</div>
							</div>
						</div>
					</div>
				</div>
			</div>
		</div>
");
			}


            // krbtgt
            GenerateSubSection("krbtgt (Used for Golden ticket attacks)");
            Add(@"
		<div class=""row""><div class=""col-lg-12"">
<p>The password of the krbtgt account should be changed twice every 40 days using this <a href=""https://gallery.technet.microsoft.com/Reset-the-krbtgt-account-581a9e51"">script</a></p>
<p>You can use the version gathered using replication metadata from two reports to guess the frequency of the password change or if the two consecutive resets has been done</p>
<p><strong>Kerberos password last changed: </strong> " + HealthCheckData.KrbtgtLastChangeDate.ToString("u") + @"
<strong>version: </strong> " + HealthCheckData.KrbtgtLastVersion + @"
</p>
		</div></div>
");
            // adminSDHolder
            GenerateSubSection("AdminSDHolder (detect temporary elevated accounts)");
            Add(@"
		<div class=""row""><div class=""col-lg-12"">
<p>This control detects accounts which are former 'unofficial' admins.
Indeed when an account belongs to a privileged group, the attribute adminaccount is set. If the attribute is set without being an official member, this is suspicious. To suppress this warning, the attribute admincount of these accounts should be removed after review.</p>
<p><strong>Number of accounts to review:</strong> " +
		(HealthCheckData.AdminSDHolderNotOKCount > 0 ? "<span class=\"unticked\">" + HealthCheckData.AdminSDHolderNotOKCount + "</span>" : "0")
	+ @"</p>
		</div></div>
");
			if (HealthCheckData.AdminSDHolderNotOKCount > 0 && HealthCheckData.AdminSDHolderNotOK != null && HealthCheckData.AdminSDHolderNotOK.Count > 0)
			{
				GenerateAccordion("adminsdholder", () => GenerateListAccountDetail("adminsdholder", "adminsdholderpanel", "AdminSDHolder User List", HealthCheckData.AdminSDHolderNotOK));
			}

			if (HealthCheckData.DomainControllers != null)
			{
				string nullsession = null;
				int countnullsession = 0;
				foreach (var DC in HealthCheckData.DomainControllers)
				{
					if (DC.HasNullSession)
					{
						nullsession += @"<TR><TD class='text'>" + DC.DCName + @"</TD></TR>";
						countnullsession++;
					}
				}
				if (countnullsession > 0)
				{
                    GenerateSubSection("NULL SESSION (anonymous access)");
                    Add(@"
		<div class=""row""><div class=""col-lg-12"">
			<p><strong>Domain controllers vulnerable:</strong> <span class=""unticked"">" + countnullsession + @"</span>
		</div></div>
		<div class=""row"">
			<div class=""col-md-12"">
				<div class=""panel-group"" id=""nullsessions"">
					<div class=""panel panel-default"">
						<div class=""panel-heading"">
							<a data-toggle=""collapse"" href=""#nullsessionPanel"" data-parent=""#nullsessions"">
								<h4 class=""panel-title"">
									Domain controllers with NULL SESSION Enabled <i class=""pull-right"">[" + countnullsession + @"]</i>
								</h4>
							</a>
						</div>
						<div id=""nullsessionPanel"" class=""panel-collapse collapse"">
							<div class=""panel-body"">
								<div class=""col-md-12 table-responsive"">
									<table class=""table table-striped table-bordered sortable-theme-bootstrap"" data-sortable="""">
									<thead><TR> 
										<Th>Domain Controller</Th>
									</TR>
									</thead>
									<tbody>
										" + nullsession + @"
									</tbody></table>
								</div>
							</div>
						</div>
					</div>
				</div>
			</div>
		</div>
");
				}

				if (HealthCheckData.SmartCardNotOK != null && HealthCheckData.SmartCardNotOK.Count > 0)
				{
                    // smart card
                    GenerateSubSection("Smart Card Password (Password change for smartcard users)");
                    Add(@"
		<div class=""row""><div class=""col-lg-12"">
			<p><strong>Users smart card and password > 40 days:</strong> " +
        (HealthCheckData.SmartCardNotOK == null ? 0 : HealthCheckData.SmartCardNotOK.Count)
        + @"</p>
		</div></div>
");
                    GenerateAccordion("anomalysmartcard", () => GenerateListAccountDetail("anomalysmartcard", "smartcard", "Smart card Password >40 days List", HealthCheckData.SmartCardNotOK));
				}

                // logon script
                GenerateSubSection("Logon scripts");
                Add(@"
		<div class=""row""><div class=""col-lg-12"">
			<p>You can check here backdoors or typo error in the scriptPath attribute</p>
		</div></div>
		<div class=""row col-lg-12 table-responsive"">
			<TABLE class=""table table-striped table-bordered sortable-theme-bootstrap"" data-sortable="""">
				<thead><TR> 
					<Th>Script Name</Th>
					<Th>Count</Th>
					</TR>
				</thead>
				<tbody>
");
				// descending sort
				HealthCheckData.LoginScript.Sort(
					(HealthcheckLoginScriptData a, HealthcheckLoginScriptData b)
						=>
					{
						return b.NumberOfOccurence.CompareTo(a.NumberOfOccurence);
					}
					);

				int number = 0;
				foreach (HealthcheckLoginScriptData script in HealthCheckData.LoginScript)
				{
                    Add(@"
<TR>
<TD class='text'>");
                    Add(Encode(String.IsNullOrEmpty(script.LoginScript.Trim()) ? "<spaces>" : script.LoginScript));
                    Add(@"</TD>
<TD class='text'>");
                    Add(script.NumberOfOccurence);
                    Add(@"</TD>
</TR>
");
					number++;
					if (number >= MaxNumberUsersInHtmlReport)
					{
						Add("<TR><TD class='text'>Output limited to ");
						Add(MaxNumberUsersInHtmlReport);
						Add(" items - add \"--no-enum-limit\" to remove that limit</td></tr>");
						break;
					}
				}
				Add(@"
				</tbody>
			</table>
		</div>
");
                // certificate
                GenerateSubSection("Certificates");
                Add(@"
		<div class=""row col-lg-12"">
			<p>This detects trusted certificate which can be used in man in the middle attacks or which can issue smart card logon certificates</p>
			<p><strong>Number of trusted certificates:</strong> " + HealthCheckData.TrustedCertificates.Count + @" 
		</div>
		<div class=""row"">
			<div class=""col-md-12"">
				<div class=""panel-group"" id=""trustedCertificates"">
					<div class=""panel panel-default"">
						<div class=""panel-heading"">
							<a data-toggle=""collapse"" href=""#trustedCertificatesPanel"" data-parent=""#trustedCertificates"">
								<h4 class=""panel-title"">
									Trusted certificates <i class=""pull-right"">[" + HealthCheckData.TrustedCertificates.Count + @"]</i>
								</h4>
							</a>
						</div>
						<div id=""trustedCertificatesPanel"" class=""panel-collapse collapse"">
							<div class=""panel-body"">
								<div class=""col-md-12 table-responsive"">
									<table class=""table table-striped table-bordered sortable-theme-bootstrap"" data-sortable="""">
									<thead><TR> 
										<Th>Source</Th>
										<Th>Store</Th>
										<Th>Subject</Th>
										<Th>Issuer</Th>
										<Th>NotBefore</Th>
										<Th>NotAfter</Th>
										<Th>Module size</Th>
										<Th>Signature Alg</Th>
										<Th>SC Logon</Th>
										</TR>
									</thead>
									<tbody>
");
				foreach (HealthcheckCertificateData data in HealthCheckData.TrustedCertificates)
				{
					X509Certificate2 cert = new X509Certificate2(data.Certificate);
					bool SCLogonAllowed = false;
					foreach (X509Extension ext in cert.Extensions)
					{
						if (ext.Oid.Value == "1.3.6.1.4.1.311.20.2.2")
						{
							SCLogonAllowed = true;
							break;
						}
					}
					int modulesize = 0;
					RSA key = null;
					try
					{
						key = cert.PublicKey.Key as RSA;
					}
					catch (Exception)
					{
					}
					if (key != null)
					{
						RSAParameters rsaparams = key.ExportParameters(false);
						modulesize = rsaparams.Modulus.Length * 8;
					}
                    Add(@"
<TR>
<TD class='text'>");
                    Add(Encode(data.Source));
                    Add(@"</TD>
<TD class='text'>");
                    Add(Encode(data.Store));
                    Add(@"</TD>
<TD class='text' class=""text-nowrap"">");
                    Add(Encode(cert.Subject));
                    Add(@"</TD>
<TD class='text' class=""text-nowrap"">");
                    Add(Encode(cert.Issuer));
                    Add(@"</TD>
<TD class='text' class=""text-nowrap"">");
                    Add(cert.NotBefore);
                    Add(@"</TD>
<TD class='text' class=""text-nowrap"">");
                    Add(cert.NotAfter);
                    Add(@"</TD>
<TD class='num'>");
                    Add(modulesize);
                    Add(@"</TD>
<TD class='text'>");
                    Add(cert.SignatureAlgorithm.FriendlyName);
                    Add(@"</TD>
<TD class='text'>");
                    Add(SCLogonAllowed);
                    Add(@"</TD>
</TR>
");
				}
				Add(@"
									</tbody></table>
								</div>
							</div>
						</div>
					</div>
				</div>
			</div>
		</div>

");
			}
		}
		#endregion anomaly

		#region password policies

		private void GeneratePasswordPoliciesDetail()
		{
            GenerateSubSection("Password policies");
            Add(@"
		<p>Note: PSO (Password Settings Objects) will be visible only if the user which collected the information has the permission to view it.<br>PSO shown in the report will be prefixed by &quot;PSO:&quot;</p>
		<div class=""row col-lg-12 table-responsive"">
			<TABLE class=""table table-striped table-bordered sortable-theme-bootstrap"" data-sortable="""">
				<thead><TR> 
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
			if (HealthCheckData.GPPPasswordPolicy != null)
			{
				foreach (GPPSecurityPolicy policy in HealthCheckData.GPPPasswordPolicy)
				{
                    Add(@"
				<TR>
					<TD class='text'>");
                    Add(Encode(policy.GPOName));
                    Add(@"</TD>
					<TD class='text'>");
                    Add(GetPSOStringValue(policy, "PasswordComplexity"));
                    Add(@"</TD>
					<TD class='num'>");
                    Add(GetPSOStringValue(policy, "MaximumPasswordAge"));
                    Add(@"</TD>
					<TD class='num'>");
                    Add(GetPSOStringValue(policy, "MinimumPasswordAge"));
                    Add(@"</TD>
					<TD class='num'>");
                    Add(GetPSOStringValue(policy, "MinimumPasswordLength"));
                    Add(@"</TD>
					<TD class='num'>");
                    Add(GetPSOStringValue(policy, "PasswordHistorySize"));
                    Add(@"</TD>
					<TD class='text'>");
                    Add(GetPSOStringValue(policy, "ClearTextPassword"));
                    Add(@"</TD>
					<TD class='num'>");
                    Add(GetPSOStringValue(policy, "LockoutBadCount"));
                    Add(@"</TD>
					<TD class='num'>");
                    Add(GetPSOStringValue(policy, "LockoutDuration"));
                    Add(@"</TD>
					<TD class='num'>");
                    Add(GetPSOStringValue(policy, "ResetLockoutCount"));
                    Add(@"</TD>
				</TR>
");
				}
			}
			Add(@"
				</tbody>
			</table>
		</div>
");
            GenerateSubSection("Screensaver policies");
            Add(@"
		<div class=""row col-lg-12 table-responsive"">
			<TABLE class=""table table-striped table-bordered sortable-theme-bootstrap"" data-sortable="""">
				<thead><TR> 
					<Th>Policy Name</Th>
					<Th>Screensaver enforced</Th>
					<Th>Password request</Th>
					<Th>Start after (seconds)</Th>
					<Th>Grace Period (seconds)</Th>
					</TR>
				</thead>
				<tbody>
");
			if (HealthCheckData.GPOScreenSaverPolicy != null)
			{
				foreach (GPPSecurityPolicy policy in HealthCheckData.GPOScreenSaverPolicy)
				{
                    Add(@"
					<TR>
						<TD class='text'>");
                    Add(Encode(policy.GPOName));
                    Add(@"</TD>
						<TD class='num'>");
                    Add(GetPSOStringValue(policy, "ScreenSaveActive"));
                    Add(@"</TD>
						<TD class='num'>");
                    Add(GetPSOStringValue(policy, "ScreenSaverIsSecure"));
                    Add(@"</TD>
						<TD class='num'>");
                    Add(GetPSOStringValue(policy, "ScreenSaveTimeOut"));
                    Add(@"</TD>
						<TD class='text'>");
                    Add(GetPSOStringValue(policy, "ScreenSaverGracePeriod"));
                    Add(@"</TD>
					</TR>
");
				}
			}
			Add(@"
				</tbody>
			</table>
		</div>
");
            GenerateSubSection("LSA settings");
            Add(@"
		<div class=""row col-lg-12 table-responsive"">
			<TABLE class=""table table-striped table-bordered sortable-theme-bootstrap"" data-sortable="""">
				<thead><TR> 
					<Th>Policy Name</Th>
					<Th>Setting</Th>
					<Th>Value</Th></tr>
				</thead>
				<tbody>");
			if (HealthCheckData.GPPPasswordPolicy != null)
			{
				foreach (GPPSecurityPolicy policy in HealthCheckData.GPOLsaPolicy)
				{
					foreach (GPPSecurityPolicyProperty property in policy.Properties)
					{
                        Add(@"
					<TR>
						<TD class='text'>");
                        Add(Encode(policy.GPOName));
                        Add(@"</TD>
						<TD class='text'>");
                        Add(GetLinkForLsaSetting(property.Property));
                        Add(@"</TD>
						<TD class='num'>");
                        Add(property.Value);
                        Add(@"</TD>
					</tr>
");
					}
				}
			}
			Add(@"
				</tbody>
			</table>
		</div>
");
		}

		#endregion password policies

		#region GPO
		private void GenerateGPODetail()
		{
            GenerateSubSection("Obfuscated Passwords");
            Add(@"
		<div class=""row col-lg-12"">
			<p>The password in GPO are obfuscated, not encrypted. Consider any passwords listed here as compromissed and change it immediatly.</p>
		</div>
");
			if (HealthCheckData.GPPPassword != null && HealthCheckData.GPPPassword.Count > 0)
			{
				Add(@"
		<div class=""row col-lg-12 table-responsive"">
			<TABLE class=""table table-striped table-bordered sortable-theme-bootstrap"" data-sortable="""">
				<thead><TR> 
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
				foreach (GPPPassword password in HealthCheckData.GPPPassword)
				{
                    Add(@"
					<TR>
						<TD class='text'>");
                    Add(Encode(password.GPOName));
                    Add(@"</TD>
						<TD class='text'>");
                    Add(Encode(password.Type));
                    Add(@"</TD>
						<TD class='text'>");
                    Add(Encode(password.UserName));
                    Add(@"</TD>
						<TD class='text'><span class=""unticked"">");
                    Add(Encode(password.Password));
                    Add(@"</span></TD>
						<TD class='text'>");
                    Add(password.Changed);
                    Add(@"</TD>
						<TD class='text'>");
                    Add(Encode(password.Other));
                    Add(@"</TD>
					</TR>
    ");
				}
				Add(@"
				</tbody>
			</table>
		</div>
");
			}

            GenerateSubSection("Restricted Groups");
            Add(@"
		<div class=""row col-lg-12"">
			<p>Giving local group membership in a GPO is a way to become administrator.<br>
			The local admin of a domain controller can become domain administrator instantly.</p>
		</div>
");
			if (HealthCheckData.GPOLocalMembership != null && HealthCheckData.GPOLocalMembership.Count > 0)
			{
				HealthCheckData.GPOLocalMembership.Sort((GPOMembership a, GPOMembership b) =>
				{
					int sort = String.Compare(a.GPOName, b.GPOName);
					if (sort == 0)
						sort = String.Compare(a.User, b.User);
					if (sort == 0)
						sort = String.Compare(a.MemberOf, b.MemberOf);
					return sort;
				}
				);
				Add(@"
		<div class=""row col-lg-12 table-responsive"">
			<TABLE class=""table table-striped table-bordered sortable-theme-bootstrap"" data-sortable="""">
				<thead><TR> 
					<Th>GPO Name</Th>
					<Th>User or group</Th>
					<Th>Member of</Th>
					</TR>
				</thead>
				<tbody>");

				foreach (GPOMembership membership in HealthCheckData.GPOLocalMembership)
				{
                    Add(@"
					<TR>
						<TD class='text'>");
                    Add(Encode(membership.GPOName));
                    Add(@"</TD>
						<TD class='text'>");
                    Add(Encode(membership.User));
                    Add(@"</TD>
						<TD class='text'>");
                    Add(Encode(membership.MemberOf));
                    Add(@"</TD>
					</TR>
");
				}
				Add(@"
				</tbody>
			</table>
		</div>
");
			}

            GenerateSubSection("Privileges");
            Add(@"
		<div class=""row col-lg-12"">
			<p>Giving privilegdes in a GPO is a way to become administrator without being part of a group.<br>
			For example, SeTcbPriviledge give the right to act as SYSTEM, which has more privileges than the administrator account.</p>
		</div>
");
			if (HealthCheckData.GPPRightAssignment != null && HealthCheckData.GPPRightAssignment.Count > 0)
			{
				Add(@"
		<div class=""row col-lg-12 table-responsive"">
			<TABLE class=""table table-striped table-bordered sortable-theme-bootstrap"" data-sortable="""">
				<thead><TR> 
					<Th>GPO Name</Th>
					<Th>Privilege</Th>
					<Th>Members</Th>
					</TR>
				</thead>
				<tbody>");

				foreach (GPPRightAssignment right in HealthCheckData.GPPRightAssignment)
				{
                    Add(@"
					<TR>
						<TD class='text'>");
                    Add(Encode(right.GPOName));
                    Add(@"</TD>
						<TD class='text'>");
                    Add(Encode(right.Privilege));
                    Add(@"</TD>
						<TD class='text'>");
                    Add(Encode(right.User));
                    Add(@"</TD>
					</TR>
");
				}
				Add(@"
				</tbody>
			</table>
		</div>
");
			}
            GenerateSubSection("GPO Login script");
            Add(@"
		<div class=""row col-lg-12"">
			<p>A GPO login script is a way to force the execution of data on behalf of users.</p>
		</div>
");
			if (HealthCheckData.GPOLoginScript != null && HealthCheckData.GPOLoginScript.Count > 0)
			{
				Add(@"
		<div class=""row col-lg-12 table-responsive"">
			<TABLE class=""table table-striped table-bordered sortable-theme-bootstrap"" data-sortable="""">
				<thead><TR> 
					<Th>GPO Name</Th>
					<Th>Action</Th>
					<Th>Source</Th>
					<Th>Command line</Th>
					<Th>Parameters</Th>
					</TR>
				</thead>
				<tbody>");

				foreach (HealthcheckGPOLoginScriptData loginscript in HealthCheckData.GPOLoginScript)
				{
                    Add(@"
					<TR>
						<TD class='text'>");
                    Add(Encode(loginscript.GPOName));
                    Add(@"</TD>
						<TD class='text'>");
                    Add(Encode(loginscript.Action));
                    Add(@"</TD>
						<TD class='text'>");
                    Add(Encode(loginscript.Source));
                    Add(@"</TD>
						<TD class='text'>");
                    Add(Encode(loginscript.CommandLine));
                    Add(@"</TD>
						<TD class='text'>");
                    Add(Encode(loginscript.Parameters));
                    Add(@"</TD>
					</TR>
");
				}
				Add(@"
				</tbody>
			</table>
		</div>
");
			}
		}
		#endregion GPO
	}
}
