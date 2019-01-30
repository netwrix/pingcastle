using PingCastle.Healthcheck;
using PingCastle.Rules;
using System;
using System.Collections.Generic;
using System.Text;

namespace PingCastle.Report
{
	public abstract class ReportRiskControls<T> : ReportBase where T : IRiskEvaluation
	{

		int GetRulesNumberForCategory(List<HealthcheckRiskRule> rules, RiskRuleCategory category)
		{
			int count = 0;
			foreach (var rule in rules)
			{
				if (rule.Category == category)
					count++;
			}
			return count;
		}

		public static string GetRiskControlStyleSheet()
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
";
		}

		#region indicators

		protected void GenerateIndicators(IRiskEvaluation data, IList<IRuleScore> rules)
		{
			GenerateSubSection("Indicators");
			Add(@"
		<div class=""row"">
			<div class=""col-md-4"">
				<div class=""chart-gauge"">");
			GenerateGauge(data.GlobalScore);
			Add(@"</div>
			</div>
			<div class=""col-md-8"">
					<p class=""lead"">Domain Risk Level: ");
			Add(data.GlobalScore.ToString());
			Add(@" / 100</p>
					<p>It is the maximum score of the 4 indicators and one score cannot be higher than 100. The lower the better</p>
			</div>
		</div>
		<div class=""row"" style=""border: 2px solid #Fa9C1A; margin:2px; padding: 2px;"">
");
			GenerateSubIndicator("Stale Object", data.GlobalScore, data.StaleObjectsScore, rules, RiskRuleCategory.StaleObjects, "It is about operations related to user or computer objects");
			GenerateSubIndicator("Trusts", data.GlobalScore, data.TrustScore, rules, RiskRuleCategory.Trusts, "It is about links between two Active Directories");
			GenerateSubIndicator("Privileged Accounts", data.GlobalScore, data.PrivilegiedGroupScore, rules, RiskRuleCategory.PrivilegedAccounts, "It is about administrators of the Active Directory");
			GenerateSubIndicator("Anomalies", data.GlobalScore, data.AnomalyScore, rules, RiskRuleCategory.Anomalies, "It is about specific security control points");
			Add(@"
		</div>
");
		}

		void GenerateSubIndicator(string category, int globalScore, int score, IList<IRuleScore> rules, RiskRuleCategory RiskRuleCategory, string explanation)
		{
			int numrules = 0;
			if (rules != null)
			{
				foreach (var rule in rules)
				{
					if (rule.Category == RiskRuleCategory)
						numrules++;
				}
			}
			GenerateSubIndicator(category, globalScore, score, numrules, explanation);
		}

		protected void GenerateSubIndicator(string category, int globalScore, int score, int numrules, string explanation)
		{
			
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
			Add((score == globalScore ? "<strong>" : ""));
			Add(@"<p>");
			Add(category);
			Add(@" : ");
			Add(score.ToString());
			Add(@" /100</p>");
			Add((score == globalScore ? "</strong>" : ""));
			Add(@"
					<p class=""small"">");
			AddEncoded(explanation);
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

		protected void GenerateRiskModelPanel(List<HealthcheckRiskRule> rules, int numberOfDomain = 1)
		{
			Add(@"
		<div class=""row""><div class=""col-lg-12"">
			<a data-toggle=""collapse"" data-target=""#riskModel"">
				<h2>Risk model</h2>
			</a>
		</div></div>
		<div class=""row collapse show"" id=""riskModel"">
			<div class=""col-md-12 table-responsive"">
				<table class=""model_table"">
					<thead><tr><th>Stale Objects</th><th>Privileged accounts</th><th>Trusts</th><th>Anomalies</th></tr></thead>
					<tbody>
");
			var riskmodel = new Dictionary<RiskRuleCategory, List<RiskModelCategory>>();
			foreach (RiskRuleCategory category in Enum.GetValues(typeof(RiskRuleCategory)))
			{
				riskmodel[category] = new List<RiskModelCategory>();
			}
			for (int j = 0; j < 4; j++)
			{
				for (int i = 0; ; i++)
				{
					int id = (1000 * j + 1000 + i);
					if (Enum.IsDefined(typeof(RiskModelCategory), id))
					{
						riskmodel[(RiskRuleCategory)j].Add((RiskModelCategory)id);
					}
					else
						break;
				}
			}
			foreach (RiskRuleCategory category in Enum.GetValues(typeof(RiskRuleCategory)))
			{
				riskmodel[category].Sort(
										(RiskModelCategory a, RiskModelCategory b) =>
										{
											return string.Compare(ReportHelper.GetEnumDescription(a), ReportHelper.GetEnumDescription(b));
										});
			}
			for (int i = 0; ; i++)
			{
				string line = "<tr>";
				bool HasValue = false;
				foreach (RiskRuleCategory category in Enum.GetValues(typeof(RiskRuleCategory)))
				{
					if (i < riskmodel[category].Count)
					{
						HasValue = true;
						RiskModelCategory model = riskmodel[category][i];
						int score = 0;
						int numrules = 0;
						List<HealthcheckRiskRule> rulematched = new List<HealthcheckRiskRule>();
						foreach (HealthcheckRiskRule rule in rules)
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
						else if (score <= 10 * numberOfDomain)
						{
							tdclass = "model_toimprove";
						}
						else if (score <= 30 * numberOfDomain)
						{
							tdclass = "model_warning";
						}
						else
						{
							tdclass = "model_danger";
						}
						string tooltip = "Rules: " + numrules + " Score: " + score / numberOfDomain;
						string tooltipdetail = null;
						string modelstring = ReportHelper.GetEnumDescription(model);
						rulematched.Sort((HealthcheckRiskRule a, HealthcheckRiskRule b)
							=>
						{
							return a.Points.CompareTo(b.Points);
						});
						foreach (var rule in rulematched)
						{
							tooltipdetail += ReportHelper.Encode(rule.Rationale) + "<br>";
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

		protected void GenerateIndicatorPanel(string id, string title, RiskRuleCategory category, List<HealthcheckRiskRule> rules)
		{
			Add(@"
		<div class=""row""><div class=""col-lg-12 mt-2"">
			<a data-toggle=""collapse"" data-target=""#" + id + @""">
				<h2>");
			Add(title);
			Add(@" [");
			Add(GetRulesNumberForCategory(rules, category).ToString());
			Add(@" rules matched]</h2>
			</a>
		</div></div>
		<div class=""row collapse show"" id=""");
			Add(id);
			Add(@"""><div class=""col-lg-12"">
");
			bool hasRule = false;
			foreach (HealthcheckRiskRule rule in rules)
			{
				if (rule.Category == category)
				{
					hasRule = true;
					break;
				}
			}
			if (hasRule)
			{
				GenerateAccordion("rules" + category.ToString(), () =>
					{
						rules.Sort((HealthcheckRiskRule a, HealthcheckRiskRule b)
							=>
						{
							return -a.Points.CompareTo(b.Points);
						}
						);
						foreach (HealthcheckRiskRule rule in rules)
						{
							if (rule.Category == category)
								GenerateIndicatorPanelDetail(category, rule);
						}
					});
			}
			else
			{
				Add("<p>No rule matched</p>");
			}
			Add(@"
			</div>
		</div>");
		}

		protected void GenerateSubIndicator(string category, int globalScore, int score, string explanation)
		{

			Add(@"
			<div class=""col-lg-12"">
				<div class=""row"">
					<div class="" col-lg-3 col-md-4 col-xs-8 col-sm-9"">
						<div class=""chart-gauge"">");
			GenerateGauge(score);
			Add(@"</div>
					</div>
					<div class=""col-lg-9 col-md-8 col-xs-8 col-sm-9"">
					");
			Add((score == globalScore ? "<strong>" : ""));
			Add(@"<p>");
			Add(category);
			Add(@" : ");
			Add(score.ToString());
			Add(@" /100</p>");
			Add((score == globalScore ? "</strong>" : ""));
			Add(@"
					<p class=""small"">");
			AddEncoded(explanation);
			Add(@"</p>
					</div>
				</div>
			</div>
");
		}

		protected void GenerateIndicatorPanelDetail(RiskRuleCategory category, HealthcheckRiskRule rule)
		{
			string safeRuleId = rule.RiskId.Replace("$", "dollar");
			GenerateAccordionDetail("rules" + safeRuleId, "rules" + category.ToString(), rule.Rationale, rule.Points, true,
				() =>
				{
					var hcrule = RuleSet<T>.GetRuleFromID(rule.RiskId);
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
					if ((rule.Details != null && rule.Details.Count > 0) || (hcrule != null && !String.IsNullOrEmpty(hcrule.ReportLocation)))
					{
						Add("<strong>Details:</strong>");
						if (!String.IsNullOrEmpty(hcrule.ReportLocation))
						{
							Add("<p>");
							Add(hcrule.ReportLocation);
							Add("</p>");
						}
						if (rule.Details != null && rule.Details.Count > 0)
						{
							Add("<p>");
							Add(String.Join("<br>\r\n", rule.Details.ToArray()));
							Add("</p>");
						}
					}
				});
		}

		#endregion indicators
	}
}
