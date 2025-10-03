using PingCastle.Healthcheck;
using PingCastle.Rules;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace PingCastle.Report
{
    public abstract class ReportRiskControls<T> : ReportBase where T : IRiskEvaluation
    {
        protected ADHealthCheckingLicense _license;

        public ReportRiskControls(ADHealthCheckingLicense license)
        {
            _license = license;
        }


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

        #region indicators

        protected void GenerateIndicators(IRiskEvaluation data, IList<IRuleScore> rules, GenerateContentDelegate statistics)
        {
            GenerateSubSection("Indicators");
            Add(@"
		<div class=""row"">
			<div class=""col-md-4 col-sm-6"">
				<div class=""chart-gauge"">");
            GenerateGauge(data.GlobalScore);
            Add(@"</div>
			</div>
			<div class=""col-md-8 col-sm-6"">
					<p class=""lead"">Domain Risk Level: ");
            Add(data.GlobalScore.ToString());
            Add(@" / 100</p>");
            AddParagraph("It is the maximum score of the 4 indicators and one score cannot be higher than 100. The lower the better");
            if (statistics != null)
                statistics();
            Add(@"
			</div>
		</div>
		<div class=""row indicators-border"">
");
            GenerateSubIndicator("Stale Object", data.GlobalScore, data.StaleObjectsScore, rules, RiskRuleCategory.StaleObjects, "It is about operations related to user or computer objects");
            GenerateSubIndicator("Trusts", data.GlobalScore, data.TrustScore, rules, RiskRuleCategory.Trusts, "It is about connections between two Active Directories");
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
		<div class=""row d-print-none"">
            <div class=""col-lg-12"">
			    <a> 
                    <h2 class=""sub-section risk-sub-section"">
                    Risk model
                    </h2>
                </a>
        <p>Left-click on the headlines in the boxes for more details</p>
		    </div>
        </div>
		<div class=""row cd-print-none"">
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
                        string tooltip = "Rules: " + numrules + " Score: " + (numberOfDomain == 0 ? 100 : score / numberOfDomain);
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
                            var hcrule = RuleSet<T>.GetRuleFromID(rule.RiskId);
                            if (hcrule != null && !string.IsNullOrEmpty(hcrule.ReportLocation))
                            {
                                tooltipdetail += "<small  class='text-muted'>" + ReportHelper.Encode(hcrule.ReportLocation) + "</small><br>";
                            }
                        }
                        line += "<td class=\"model_cell " + tdclass + "\"><div class=\"div_model\" placement=\"auto right\" data-bs-toggle=\"popover\" title=\"" +
                            tooltip + "\" data-bs-html=\"true\" data-bs-content=\"" +
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
		<div class=""mb-2"">Legend: <br></div>
            <i class=""risk_model_no_detections"">&nbsp;</i> score is 0 - no risk identified<br>
			<i class=""risk_model_none"">&nbsp;</i> score is 0 - no risk identified but some improvements detected<br>
			<i class=""risk_model_low"">&nbsp;</i> score between 1 and 10  - a few actions have been identified<br>
			<i class=""risk_model_medium"">&nbsp;</i> score between 10 and 30 - rules should be looked with attention<br>
			<i class=""risk_model_high"">&nbsp;</i> score higher than 30 - major risks identified<br>
			</div>
		</div>");
        }

        protected void GenerateIndicatorPanel(string id, string title, RiskRuleCategory category, List<HealthcheckRiskRule> rules, List<RuleBase<HealthcheckData>> applicableRules)
        {
            Add(@"
		<div class=""row""><div class=""col-lg-12 mt-2"">
			<a data-bs-toggle=""collapse"" data-bs-target=""#" + id + @""">
				<h2>");
            Add(title);
            Add(@" [");
            Add(GetRulesNumberForCategory(rules, category).ToString());
            Add(@" rules matched on a total of ");
            Add(GetApplicableRulesNumberForCategory(applicableRules, category).ToString());
            Add(@"]</h2>
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
                                GenerateIndicatorPanelDetail(category.ToString(), rule);
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

        private int GetApplicableRulesNumberForCategory(List<RuleBase<HealthcheckData>> applicableRules, RiskRuleCategory category)
        {
            int count = 0;
            foreach (var rule in applicableRules)
            {
                if (rule.Category == category)
                    count++;
            }
            return count;
        }

        protected void GenerateSubIndicatorHeader(string category, int globalScore, int score, string explanation)
        {

            Add(@"
			<div class="""">
				<div class=""row"">
					<div class="" col-lg-3 col-md-4 col-xs-6 col-sm-6"">
						<div class=""chart-gauge"">");
            GenerateGauge(score);
            Add(@"</div>
					</div>
					<div class=""col-lg-9 col-md-8 col-xs-6 col-sm-6"">
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

        public IActionPlan ActionPlanOrchestrator { get; set; }

        protected void GenerateAccordionDetailForRule(string id, string dataParent, string title, HealthcheckRiskRule rule, RuleBase<HealthcheckData> hcrule, GenerateContentDelegate content)
        {
            GenerateAccordionDetail(id, dataParent, title,
                () =>
                {
                    if (rule.Points == 0)
                    {
                        Add(@"<i class=""float-end""><span class='float-end'>Informative rule</span>");
                        if (ActionPlanOrchestrator != null)
                        {
                            ActionPlanOrchestrator.GenerateMainActionPlan(sb, rule, hcrule);
                        }
                        Add("</i>");
                    }
                    else
                    {
                        Add(@"<i class=""float-end""><span class='float-end'>+ ");
                        Add(rule.Points);
                        Add(@" Point(s)</span>");
                        if (ActionPlanOrchestrator != null)
                        {
                            ActionPlanOrchestrator.GenerateMainActionPlan(sb, rule, hcrule);
                        }
                        Add("</i>");
                    }
                }, content);
        }

        List<string> GetTokens(List<string> details)
        {
            if (details == null || details.Count == 0 || string.IsNullOrEmpty(details[0]))
                return null;
            var tokens = GetTokens(details[0]);
            if (tokens == null)
                return null;

            foreach (var detail in details.Skip(1))
            {
                var curTokens = GetTokens(detail);
                if (curTokens == null)
                    return null;

                tokens.RemoveAll(t => !curTokens.Contains(t));
            }
            return tokens;
        }

        List<string> GetTokens(string detail)
        {
            if (string.IsNullOrEmpty(detail))
                return null;

            detail = detail.Replace("Domain controller:", "Domain_controller:");
            
            var items = detail.Split(' ');
            if (items.Length <= 1 || !items[0].EndsWith(":"))
                return null;

            var tokens = new List<string>();
            foreach (var item in items)
            {
                if (!string.IsNullOrEmpty(item) && item.EndsWith(":"))
                {
                    var itemWithoutDetiailIndex = Regex.Replace(item, "<.*?>", "");
                    tokens.Add(itemWithoutDetiailIndex);
                }
            }
            return tokens;
        }
              
        private void AddExtendedDetailInfo(ExtraDetail detail)
        {
            if (detail?.DetailItems == null)
                return;

            AddBeginTooltip(true, true);

            Add($"<div class='text-start'>Details:<br><ul>");

            foreach (var item in detail.DetailItems)
            {
                Add("<li>");

                switch (item)
                {
                    case ListDetailItem list:
                        {
                            Add($"{list.Name}<ul>");
                            foreach (var value in list.Values)
                            {
                                Add("<li>");
                                AddEncoded(value);
                                Add("</li>");
                            }
                            Add("</ul>");
                        }
                        break;
                    case TextDetailItem text:
                        {
                            AddEncoded($"{text.Name}: {text.Value}");
                        }
                        break;
                }

                Add("</li>");
            }

            Add("</ul></div>");

            AddEndTooltip();
        }

        protected void GenerateIndicatorPanelDetail(string category, HealthcheckRiskRule rule, string optionalId = null)
        {
            string safeRuleId = rule.RiskId.Replace("$", "dollar");
            var hcrule = RuleSet<HealthcheckData>.GetRuleFromID(rule.RiskId);
            GenerateAccordionDetailForRule("rules" + optionalId + safeRuleId, "rules" + category, rule.Rationale, rule, hcrule,
                () =>
                {
                    if (hcrule == null)
                    {
                    }
                    else
                    {
                        Add("<h3>");
                        Add(hcrule.Title);
                        Add("</h3>\r\n");

                        if (!string.IsNullOrEmpty(rule.Notice))
                        {
                            Add($"<div class=\"alert alert-info warn\">{NewLineToBR(rule.Notice)}");
                            if(!string.IsNullOrEmpty(rule.NoticeTooltip))
                            {
                                AddBeginTooltip(true, true);
                                Add($"<div class='text-start'>{NewLineToBR(rule.NoticeTooltip)}</div>");
                                AddEndTooltip();
                            }
                            Add("</div>");
                            Add("<br>"); 
                        }

                        Add("<strong>Rule ID:</strong><p class=\"text-justify\">");
                        Add(hcrule.RiskId);
                        Add("</p>\r\n<strong>Description:</strong><p class=\"text-justify\">");
                        Add(NewLineToBR(hcrule.Description));
                        Add("</p>\r\n<strong>Technical explanation:</strong><p class=\"text-justify\">");
                        Add(NewLineToBR(hcrule.TechnicalExplanation));
                        Add("</p>\r\n<strong>Advised solution:</strong><p class=\"text-justify\">");
                        Add(NewLineToBR(hcrule.Solution));
                        Add("</p>\r\n");
                        if (_license.IsBasic() && hcrule.RelevantProducts != null)
                            Add(GenerateRelevantProductsElement(hcrule.RiskId.Replace("-", "_"), hcrule.RelevantProducts));
                        Add("<strong>Points:</strong><p>");
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
                        if (hcrule != null && !String.IsNullOrEmpty(hcrule.ReportLocation))
                        {
                            Add("<p>");
                            Add(hcrule.ReportLocation);
                            Add("</p>");
                        }
                        if (rule.Details != null && rule.Details.Count > 0 && !string.IsNullOrEmpty(rule.Details[0]))
                        {
                            var tokens = GetTokens(rule.Details);
                            if (tokens != null && tokens.Count > 0)
                            {
                                Add(@"<div class=""row"">
			<div class=""col-md-12 table-responsive"">
				<table class=""table table-striped table-bordered"">
					<thead><tr>");
                                foreach (var token in tokens)
                                {
                                    Add("<th>");
                                    AddEncoded(token.Replace("Domain_controller:", "Domain controller:").Substring(0, token.Length - 1));
                                    Add("</th>");
                                }
                                if (ActionPlanOrchestrator != null)
                                {
                                    Add("<th>Action Plan</th>");
                                }
                                Add("</tr></thead><tbody>");
                                foreach (var detail in rule.Details)
                                {
                                    if (string.IsNullOrEmpty(detail))
                                        continue;
                                    Add("<tr>");

                                    var t = detail.Replace("Domain controller:", "Domain_controller:").Split(' ');

                                    var currentDetailIndex = -1;
                                    var previousDetailIndex = -1;

                                    for (int i = 0, j = 0; i < t.Length && j <= tokens.Count; i++)
                                    {
                                        var item = t[i];

                                        if (item.StartsWith("<"))
                                        {
                                            var namePosition = item.IndexOf('>', 1);
                                            var temp = item.Substring(namePosition + 1);

                                            var strIndex = item.Substring(1, namePosition - 1);
                                            item = temp;
                                                                                       
                                            if (!int.TryParse(strIndex, out currentDetailIndex))
                                            {
                                                continue;
                                            }
                                        }

                                        if (j < tokens.Count && item == tokens[j])
                                        {
                                            if (j != 0)
                                            {
                                                if (previousDetailIndex != -1)
                                                {
                                                    AddExtendedDetailInfo(rule.ExtraDetails[previousDetailIndex]);
                                                    previousDetailIndex = -1;
                                                }

                                                Add("</td>");
                                            }

                                            previousDetailIndex = currentDetailIndex;
                                            currentDetailIndex = -1;

                                            j++;
                                            Add("<td>");
                                           
                                        }
                                        else
                                        {
                                            Add(item);
                                            Add(" ");
                                        }
                                    }
                                    Add("</td>");
                                    if (ActionPlanOrchestrator != null)
                                    {
                                        Add("<td>");
                                        ActionPlanOrchestrator.GenerateDetailledActionPlan(sb, rule, hcrule, detail);
                                        Add("</td>");
                                    }
                                    Add("</tr>");
                                }
                                Add("</tbody></table></div></div>");

                            }
                            else
                            {
                                Add("<p>");
                                Add(String.Join("<br>\r\n", rule.Details));
                                Add("</p>");
                            }
                        }
                    }
                });
        }

        protected string GenerateRelevantProductsElement(string ruleName, string relevantProductsVerbiage)
        {
            var sb = new StringBuilder(1000);
            sb.AppendLine($"<div class=\"relevantproductsheader mb-2\" data-bs-toggle=\"collapse\" aria-expanded=\"false\" href=\"#relevantProducts_{ruleName}\" aria-controls=\"relevantProducts_{ruleName}\">");
            sb.AppendLine("<span class=\"icon-container ms-0\">");
            sb.AppendLine("<span class=\"icon icon-down\">");
            sb.AppendLine("<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 512 512\">");
            sb.AppendLine("<path d=\"M233.4 406.6c12.5 12.5 32.8 12.5 45.3 0l192-192c12.5-12.5 12.5-32.8 0-45.3s-32.8-12.5-45.3 0L256 338.7 86.6 169.4c-12.5-12.5-32.8-12.5-45.3 0s-12.5 32.8 0 45.3l192 192z\" />");
            sb.AppendLine("</svg>");
            sb.AppendLine("</span>");
            sb.AppendLine("<span class=\"icon icon-up\">");
            sb.AppendLine("<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 512 512\">");
            sb.AppendLine("<path d=\"M233.4 105.4c12.5-12.5 32.8-12.5 45.3 0l192 192c12.5 12.5 12.5 32.8 0 45.3s-32.8 12.5-45.3 0L256 173.3 86.6 342.6c-12.5 12.5-32.8 12.5-45.3 0s-12.5-32.8 0-45.3l192-192z\" />");
            sb.AppendLine("</svg>");
            sb.AppendLine("</span>");
            sb.AppendLine("</span>");
            sb.AppendLine("<strong>Relevant Netwrix Products</strong>");
            sb.AppendLine("</div>");
            sb.AppendLine($"<div class=\"card-body collapse pb-0 pt-0\" id=\"relevantProducts_{ruleName}\">");
            sb.AppendLine("<ul class=\"list-unstyled mb-0\">");

            var products = relevantProductsVerbiage.Split(new[] { @"\r\n" }, StringSplitOptions.None);
            foreach (var product in products)
            {
                var parts = product.Split('|');
                if (ReportBase.RelevantProductsLinks.TryGetValue(parts[0], out string productLink))
                    sb.AppendLine($"<li class=\"icon-padded-text\">{productLink}{parts[1]}</li>");
                else
                    sb.AppendLine($"<li class=\"icon-padded-text\">{product}</li>");
            }

            sb.AppendLine("</ul>");
            sb.AppendLine("</div>");
            sb.AppendLine("<br>");
            sb.AppendLine("<p></p>\r\n");

            return sb.ToString();
        }
        #endregion indicators
    }
}
