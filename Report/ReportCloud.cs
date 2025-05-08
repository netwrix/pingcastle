//
// Copyright (c) Vincent LE TOUX for Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using Newtonsoft.Json;
using PingCastle.Rules;
using PingCastle.template;
using PingCastle.Cloud.Data;
using PingCastle.Cloud.Rules;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Net.Mail;
using PingCastle.Data;

namespace PingCastle.Report
{
    public class ReportCloud : ReportBase
    {
        public string GenerateReportFile(HealthCheckCloudData report, ADHealthCheckingLicense license, string filename)
        {
            Report = report;
            _license = license;
            Brand(license);
            return GenerateReportFile(filename);
        }

        public static int MaxNumberUsersInHtmlReport = 100;
        public static string MaxNumberUsersInHtmlReportMessage = "Output limited to {0} items - go to the advanced menu before running the report or add \"--no-enum-limit\" to remove that limit";
        
        public IAADActionPlan ActionPlanOrchestrator { get; set; }

        protected HealthCheckCloudData Report;
        protected ADHealthCheckingLicense _license;

        public string GenerateRawContent(HealthCheckCloudData report, ADHealthCheckingLicense license)
        {
            Report = report;
            _license = license;
            sb.Length = 0;
            GenerateContent();
            return sb.ToString();
        }

        protected override void GenerateTitleInformation()
        {
            AddEncoded(Report.TenantName);
            Add(" PingCastle ");
            Add(Report.GenerationDate.ToString("yyyy-MM-dd"));
        }

        protected override void ReferenceJSAndCSS()
        {
            AddStyle(TemplateManager.LoadBootstrapTableCss());
            AddStyle(TemplateManager.LoadReportBaseCss());
            AddStyle(TemplateManager.LoadReportRiskControlsCss());
            AddScript(TemplateManager.LoadBootstrapTableJs());
            AddScript(TemplateManager.LoadReportBaseJs());
            AddScript(TemplateManager.LoadReportCloudMainJs());
        }

        protected override void GenerateBodyInformation()
        {
            GenerateNavigation("HealthCheck report", Report.TenantName, Report.GenerationDate);
            GenerateAbout();
            Add(@"
<div id=""wrapper"" class=""container well"">
	<noscript>
		<div class=""alert alert-warning"">
			<p>PingCastle reports work best with Javascript enabled.</p>
		</div>
	</noscript>
<div class=""row""><div class=""col-lg-12""><h1>");
            Add(Report.TenantName);
            Add(@" - Healthcheck analysis</h1>
			<h3>Date: ");
            Add(Report.GenerationDate.ToString("yyyy-MM-dd"));
            Add(@" - Engine version: ");
            Add(Report.EngineVersion);
            Add(@"</h3>
");
            Add(@"<div class=""alert alert-info"">
This report has been generated with the ");
            Add(_license.IsBasic() ? "Basic" : _license.Edition);
            Add(@" Edition of PingCastle");
            if (!string.IsNullOrEmpty(_license.CustomerNotice))
            {
                Add(@"&nbsp;<i class=""info-mark d-print-none"" data-bs-placement=""bottom"" data-bs-toggle=""tooltip""");
                Add(@" title="""" data-bs-original-title=""");
                AddEncoded(_license.CustomerNotice);
                Add(@""">?</i>.");
            }
            if (_license.IsBasic())
            {
                Add(@"
<br><strong class='auditor'>Being part of a commercial package is forbidden</strong> (selling the information contained in the report).<br>
If you are an auditor, you MUST purchase an Auditor license to share the development effort.");
            }
            Add(@"</div>
");
            Add(@"</div></div>
");
            GenerateContent();
            Add(@"
</div>
");
        }

        protected void GenerateContent()
        {
            GenerateSection("AzureAD Indicators", () =>
            {
                AddParagraph("This section focuses on the core security indicators.<br>Locate the sub-process determining the score and fix some rules in that area to get a score improvement.");
                GenerateIndicators();
            });
            GenerateSection("Maturity Level", GenerateMaturityInformation);
            GenerateSection("MITRE ATT&CK&#174;", GenerateMitreAttackInformation);
            GenerateSection("Rules", () =>
            {
                GenerateIndicatorPanel("DetailStale", "All rule details", Report.RiskRules);
            });
            GenerateSection("Tenant Information", GenerateTenantInformation);
            GenerateSection("On premise Information", GenerateOnPremiseInformation);
            GenerateSection("Internet Presence", GenerateInternetPresenceInformation);
            GenerateSection("External Tenants", GenerateExternalTenantsInformation);
            GenerateSection("Users", GenerateUsersInformation);
            GenerateSection("Admins", GenerateAdminsInformation);
            GenerateSection("Applications", GenerateApplicationInformation);
            GenerateSection("Outlook online", GenerateOutlookOnlineInformation);
        }

        protected override void GenerateFooterInformation()
        {
        }

        protected void GenerateIndicators()
        {
            GenerateSubSection("Indicators");
            Add(@"
		<div class=""row"">
			<div class=""col-md-4"">
				<div class=""chart-gauge"">");
            GenerateGauge(Report.GlobalScore);
            Add(@"</div>
			</div>
			<div class=""col-md-8"">
					<p class=""lead"">Domain Risk Level: ");
            Add(Report.GlobalScore.ToString());
            Add(@" / 100</p>");
            AddParagraph("It is the score computed based on the rules that matched during the analysis");
            Add(@"
			</div>
		</div>
");

        }

        protected void GenerateIndicatorPanel(string id, string title, List<HealthCheckCloudDataRiskRule> rules)
        {
            Add(@"
		<div class=""row""><div class=""col-lg-12 mt-2"">
			<a data-bs-toggle=""collapse"" data-bs-target=""#" + id + @""">
				<h2>");
            Add(title);
            /*Add(@" [");
            Add(GetRulesNumberForCategory(rules, category).ToString());
            Add(@" rules matched on a total of ");
            Add(GetApplicableRulesNumberForCategory(applicableRules, category).ToString());*/
            Add(@"</h2>
			</a>
		</div></div>
		<div class=""row collapse show"" id=""");
            Add(id);
            Add(@"""><div class=""col-lg-12"">
");
            bool hasRule = false;
            foreach (HealthCheckCloudDataRiskRule rule in rules)
            {
                //if (rule.Category == category)
                {
                    hasRule = true;
                    break;
                }
            }
            if (hasRule)
            {
                GenerateAccordion("rules" + "Rules", () =>
                {
                    rules.Sort((HealthCheckCloudDataRiskRule a, HealthCheckCloudDataRiskRule b)
                        =>
                    {
                        return -a.Points.CompareTo(b.Points);
                    }
                    );
                    foreach (HealthCheckCloudDataRiskRule rule in rules)
                    {
                        GenerateIndicatorPanelDetail("Rules", rule);
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

        List<string> GetTokens(List<string> details)
        {
            if (details == null || details.Count == 0 || string.IsNullOrEmpty(details[0]))
                return null;
            var tokens = GetTokens(details[0]);
            if (tokens == null)
                return null;
            for (int i = 1; i < details.Count; i++)
            {
                var t = GetTokens(details[i]);
                if (t == null)
                    return null;
                var toRemove = new List<string>();
                foreach (var t1 in tokens)
                {
                    if (!t.Contains(t1))
                        toRemove.Add(t1);
                }
                foreach (var t1 in toRemove)
                {
                    tokens.Remove(t1);
                }
            }
            return tokens;
        }

        List<string> GetTokens(string detail)
        {
            if (string.IsNullOrEmpty(detail))
                return null;
            var tokens = new List<string>();
            var test = detail.Replace("Domain controller:", "Domain_controller:").Split(' ');
            if (test.Length <= 1 || !test[0].EndsWith(":"))
                return null;
            for (int i = 0; i < test.Length; i++)
            {
                if (!string.IsNullOrEmpty(test[i]) && test[i].EndsWith(":"))
                {
                    tokens.Add(test[i]);
                }
            }
            return tokens;
        }

        protected void GenerateIndicatorPanelDetail(string category, HealthCheckCloudDataRiskRule rule, string optionalId = null)
        {
            string safeRuleId = rule.RiskId.Replace("$", "dollar");
            var hcrule = RuleSet<HealthCheckCloudData>.GetRuleFromID(rule.RiskId);
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
                        Add("</h3>\r\n<strong>Rule ID:</strong><p class=\"text-justify\">");
                        Add(hcrule.RiskId);
                        Add("</p>\r\n<strong>Description:</strong><p class=\"text-justify\">");
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
                                foreach (var d in rule.Details)
                                {
                                    if (string.IsNullOrEmpty(d))
                                        continue;
                                    Add("<tr>");
                                    var t = d.Replace("Domain controller:", "Domain_controller:").Split(' ');
                                    for (int i = 0, j = 0; i < t.Length && j <= tokens.Count; i++)
                                    {
                                        if (j < tokens.Count && t[i] == tokens[j])
                                        {
                                            if (j != 0)
                                                Add("</td>");
                                            j++;
                                            Add("<td>");
                                        }
                                        else
                                        {
                                            Add(t[i]);
                                            Add(" ");
                                        }
                                    }
                                    Add("</td>");
                                    if (ActionPlanOrchestrator != null)
                                    {
                                        Add("<td>");
                                        ActionPlanOrchestrator.GenerateDetailledActionPlan(sb, rule, hcrule, d);
                                        Add("</td>");
                                    }
                                    Add("</tr>");
                                }
                                Add("</tbody></table></div></div>");

                            }
                            else
                            {
                                Add("<p>");
                                Add(String.Join("<br>\r\n", rule.Details.ToArray()));
                                Add("</p>");
                            }
                        }
                    }
                });
        }

        protected void GenerateAccordionDetailForRule(string id, string dataParent, string title, HealthCheckCloudDataRiskRule rule, RuleBase<HealthCheckCloudData> hcrule, GenerateContentDelegate content)
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
        #region maturity

        protected void GenerateMaturityInformation()
        {
            Add(@"<p>This section represents the maturity score (inspired from <a href='https://www.cert.ssi.gouv.fr/dur/CERTFR-2020-DUR-001/'>ANSSI</a>).</p>");
            if (_license.IsBasic())
            {
                AddParagraph("This feature is reserved for customers who have <a href='https://www.pingcastle.com/services/'>purchased a license</a>");
                return;
            }
            var data = GetCurrentMaturityLevel();
            Add("<div class='row'><div class='col-sm-6 my-auto'><p class='display-4'>Maturity Level:</span></div><div class='col-sm-6'>");
            for (int i = 1; i <= 5; i++)
            {
                if (Report.MaturityLevel == i)
                {
                    Add("<span class=\"display-1\">");
                }
                Add("<span class=\"badge grade-");
                Add(i);
                Add("\">");
                Add(i);
                Add("</span>");
                if (Report.MaturityLevel == i)
                {
                    Add("</span>");
                }
            }
            Add("</div></div>");

            Add(@"<p>Maturity levels:<p>
<ul>
    <li><span class='badge grade-1'>1</span> Critical weaknesses and misconfigurations pose an immediate threat to all hosted resources. Corrective actions should be taken as soon as possible;</li>
	<li><span class='badge grade-2'>2</span> Configuration and management weaknesses put all hosted resources at risk of a short-term compromise. Corrective actions should be carefully planned and implemented shortly;</li>
    <li><span class='badge grade-3'>3</span> The Active Directory infrastructure does not appear to have been weakened from what default installation settings provide;</li>
    <li><span class='badge grade-4'>4</span> The Active Directory infrastructure exhibits an enhanced level of security and management;</li>
    <li><span class='badge grade-5'>5</span> The Active Directory infrastructure correctly implements the latest state-of-the-art administrative model and security features.</li>
</ul>");

            Add("<div class='row'><div class='col-lg-12'>");
            Add("<div class='row row-cols-5'>");
            for (int i = 1; i <= 5; i++)
            {
                Add("<div class='col'>");
                Add("<div class='card'>");
                Add("<div class='card-body'>");
                Add("<h5 class='card-title'>");
                Add("<span class=\"badge grade-");
                Add(i);
                Add("\">");
                Add("Level ");
                Add(i);
                Add("</span>");
                Add("</h5>");
                if (data.ContainsKey(i))
                {
                    Add("<p class='card-text'>");
                    if (Report.MaturityLevel == i)
                        Add("<strong>");
                    Add(data[i].Count);
                    Add(" rule(s) matched");
                    if (Report.MaturityLevel == i)
                        Add("</strong>");
                    Add("</p>");
                }
                else
                {
                    Add("<p class='card-text'>No rule matched</p>");
                }
                Add("</div>");
                Add("</div>");
                Add("</div>");
            }
            Add("</div>");
            Add("</div></div>");

            if (data.Count > 0)
            {
                Add("<div class='row mt-4'><div class='col-lg-12'>");
                Add(@"<ul class=""nav nav-tabs d-none1"">");
                bool first = true;
                for (int i = 1; i <= 5; i++)
                {
                    if (data.ContainsKey(i) && data[i].Count > 0)
                    {
                        Add("<li class='nav-item bg-light'>");
                        Add(@"<a class='nav-link");
                        if (first)
                        {
                            Add(" active");
                            first = false;
                        }
                        Add(@"' data-bs-toggle=""tab"" href=""#maturitylevel");
                        Add(i);
                        Add(Report.GenerationDate.ToFileTime().ToString());
                        Add(@""">");
                        Add("<span class=\"badge grade-");
                        Add(i);
                        Add("\">");
                        Add("Level ");
                        Add(i);
                        Add("</span> ");
                        Add("</a>");
                        Add("</li>");
                    }
                }
                Add("</ul>");
                Add("</div></div>");
            }

            Dictionary<int, int> nextLevels = new Dictionary<int, int>();
            int start = Report.MaturityLevel;
            for (int i = start + 1; i < 6; i++)
            {
                if (data.ContainsKey(i) && data[i].Count > 0)
                {
                    if (!nextLevels.ContainsKey(start))
                        nextLevels[start] = i;
                    start = i;
                }
            }
            if (Report.MaturityLevel < 5 && !nextLevels.ContainsKey(Report.MaturityLevel))
                nextLevels[Report.MaturityLevel] = 5;
            Add("<div class='row'><div class='col-lg-12'>");
            Add(@"<div class=""tab-content"">");
            for (int i = Report.MaturityLevel; i < 6; i++)
            {
                if (data.ContainsKey(i) && data[i].Count > 0)
                {
                    var l = data[i];


                    Add(@"<div id=""maturitylevel");
                    Add(i);
                    Add(Report.GenerationDate.ToFileTime().ToString());
                    Add(@""" class=""tab-pane");
                    if (i == Report.MaturityLevel)
                    {
                        Add(" active");
                    }
                    Add(@""">");


                    Add("<p class='mt-2'>");

                    if (nextLevels.ContainsKey(i))
                    {
                        Add("To reach ");
                        var nextLevel = nextLevels[i];
                        Add("<span class=\"badge grade-");
                        Add(nextLevel);
                        Add("\">");
                        Add("Level ");
                        Add(nextLevel);
                        Add("</span> ");
                    }
                    else
                    {
                        Add("To reach the maximum level ");
                    }
                    /*Add("From ");
                    Add("<span class=\"badge grade-");
                    Add(level);
                    Add("\">");
                    Add("Level ");
                    Add(level);
                    Add("</span> ");*/
                    Add(" you need to fix the following rules:</p>");
                    GenerateAccordion("rulesmaturity" + i, () =>
                    {
                        Report.RiskRules.Sort((HealthCheckCloudDataRiskRule a, HealthCheckCloudDataRiskRule b)
                            =>
                        {
                            return -a.Points.CompareTo(b.Points);
                        }
                        );
                        foreach (HealthCheckCloudDataRiskRule rule in Report.RiskRules)
                        {
                            if (l.Contains(rule.RiskId))
                                GenerateIndicatorPanelDetail("maturity" + i, rule, "maturity" + i);
                        }
                    });
                    Add("</div>");
                }
            }
            Add("</div>");
            Add("</div></div>");

        }

        private Dictionary<int, List<string>> GetCurrentMaturityLevel()
        {
            var output = new Dictionary<int, List<string>>();
            foreach (var rule in Report.RiskRules)
            {
                var hcrule = RuleSet<HealthCheckCloudData>.GetRuleFromID(rule.RiskId);
                if (hcrule == null)
                {
                    continue;
                }
                int level = hcrule.MaturityLevel;
                if (!output.ContainsKey(level))
                    output[level] = new List<string>();
                output[level].Add(hcrule.RiskId);
            }
            return output;
        }
        #endregion

        #region mitre

        protected void GenerateMitreAttackInformation()
        {
            AddParagraph(@"This section represents an evaluation of the techniques available in the <a href=""https://attack.mitre.org/"">MITRE ATT&CK&#174;</a>");
            if (_license.IsBasic())
            {
                AddParagraph("This feature is reserved for customers who have <a href='https://www.pingcastle.com/services/'>purchased a license</a>");
                return;
            }
            GenerateMitreTechnique();
            GenerateMitreMitigation();
        }

        void GenerateMitreTechnique()
        {
            var reference = new Dictionary<RuleMitreAttackTechniqueAttribute, List<HealthCheckCloudDataRiskRule>>();
            foreach (var rule in Report.RiskRules)
            {
                var hcrule = RuleSet<HealthCheckCloudData>.GetRuleFromID(rule.RiskId);
                if (hcrule == null)
                {
                    continue;
                }
                object[] frameworks = hcrule.GetType().GetCustomAttributes(typeof(RuleMitreAttackTechniqueAttribute), true);
                foreach (RuleMitreAttackTechniqueAttribute f in frameworks)
                {
                    if (!reference.ContainsKey(f))
                    {
                        reference[f] = new List<HealthCheckCloudDataRiskRule>();
                    }
                    reference[f].Add(rule);
                }
            }
            var keys = new List<RuleMitreAttackTechniqueAttribute>(reference.Keys);
            keys.Sort((RuleMitreAttackTechniqueAttribute a, RuleMitreAttackTechniqueAttribute b) => { return string.Compare(a.Label, b.Label); });

            Add("<h2>Techniques</h2>");
            // CARDS
            Add("<div class='row'><div class='col-lg-12'>");
            Add("<div class='row row-cols-" + Enum.GetValues(typeof(MitreAttackMainTechnique)).Length + "'>");
            foreach (MitreAttackMainTechnique mainTechnique in Enum.GetValues(typeof(MitreAttackMainTechnique)))
            {
                Add("<div class='col'>");
                Add("<div class='card'>");
                Add("<div class='card-body'>");
                Add("<h5 class='card-title'>");
                var description = ReportHelper.GetEnumDescription(mainTechnique);
                Add(description);
                Add("</h5>");
                int num = 0;
                foreach (var l in keys)
                {
                    if (l.MainTechnique != mainTechnique)
                        continue;
                    num++;
                }
                if (num > 0)
                {
                    Add("<p class='card-text'>");
                    Add(num);
                    Add(" technique(s) matched");
                    Add("</p>");
                }
                else
                {
                    Add("<p class='card-text'>No technique matched</p>");
                }
                Add("</div>");
                Add("</div>");
                Add("</div>");
            }
            Add("</div>");
            Add("</div></div>");


            // tab header
            if (reference.Count > 0)
            {
                Add("<div class='row mt-4'><div class='col-lg-12'>");
                Add(@"<ul class=""nav nav-tabs d-none1"">");
                bool first = true;
                foreach (MitreAttackMainTechnique mainTechnique in Enum.GetValues(typeof(MitreAttackMainTechnique)))
                {
                    int num = 0;
                    foreach (var l in keys)
                    {
                        if (l.MainTechnique != mainTechnique)
                            continue;
                        num++;
                    }
                    if (num > 0)
                    {
                        Add("<li class='nav-item bg-light'>");
                        Add(@"<a class='nav-link");
                        if (first)
                        {
                            Add(" active");
                            first = false;
                        }
                        Add(@"' data-bs-toggle=""tab"" href=""#mitre");
                        Add(mainTechnique.ToString());
                        Add(Report.GenerationDate.ToFileTime().ToString());
                        Add(@""">");
                        var description = ReportHelper.GetEnumDescription(mainTechnique);
                        Add(description);
                        Add("</a>");
                        Add("</li>");
                    }
                }
                Add("</ul>");
                Add("</div></div>");


                // tab content
                Add("<div class='row'><div class='col-lg-12'>");
                Add(@"<div class=""tab-content"">");
                first = true;
                foreach (MitreAttackMainTechnique mainTechnique in Enum.GetValues(typeof(MitreAttackMainTechnique)))
                {
                    int num = 0;
                    foreach (var l in keys)
                    {
                        if (l.MainTechnique != mainTechnique)
                            continue;
                        num++;
                    }
                    if (num > 0)
                    {

                        Add(@"<div id=""mitre");
                        Add(mainTechnique.ToString());
                        Add(Report.GenerationDate.ToFileTime().ToString());
                        Add(@""" class=""tab-pane");
                        if (first)
                        {
                            Add(" active");
                            first = false;
                        }
                        Add(@""">");

                        Add("<div class='row'><div class='col-lg-12'>");
                        var description = ReportHelper.GetEnumDescription(mainTechnique);
                        Add("<p class='mt-2'><strong>" + description + "</strong></p>");

                        foreach (var l in keys)
                        {
                            if (l.MainTechnique != mainTechnique)
                                continue;
                            //title
                            Add("<p class='mt-2'><a href=");
                            Add(((RuleFrameworkReference)l).URL);
                            Add(">");
                            Add(((RuleFrameworkReference)l).Label);
                            Add("</a> [");
                            Add(reference[l].Count);
                            Add("]</p>");
                            GenerateAccordion("rulesmitre" + l.ID + l.SubID, () =>
                            {
                                reference[l].Sort((HealthCheckCloudDataRiskRule a, HealthCheckCloudDataRiskRule b) => { return -a.Points.CompareTo(b.Points); });
                                foreach (HealthCheckCloudDataRiskRule rule in reference[l])
                                {
                                    GenerateIndicatorPanelDetail("mitre" + l.ID + l.SubID, rule, "mitre" + l.ID + l.SubID);
                                }
                            });
                        }
                        Add("</div></div>");
                        Add("</div>");
                    }
                }
                Add("</div>");
                Add("</div></div>");
            }

        }

        void GenerateMitreMitigation()
        {
            var reference = new Dictionary<RuleMitreAttackMitigationAttribute, List<HealthCheckCloudDataRiskRule>>();
            int notcovered = 0;
            foreach (var rule in Report.RiskRules)
            {
                var hcrule = RuleSet<HealthCheckCloudData>.GetRuleFromID(rule.RiskId);
                if (hcrule == null)
                {
                    continue;
                }
                object[] frameworks = hcrule.GetType().GetCustomAttributes(typeof(RuleMitreAttackMitigationAttribute), true);
                if (frameworks == null || frameworks.Length == 0)
                    notcovered++;
                foreach (RuleMitreAttackMitigationAttribute f in frameworks)
                {
                    if (!reference.ContainsKey(f))
                    {
                        reference[f] = new List<HealthCheckCloudDataRiskRule>();
                    }
                    reference[f].Add(rule);
                }
            }
            var keys = new List<RuleMitreAttackMitigationAttribute>(reference.Keys);
            keys.Sort((RuleMitreAttackMitigationAttribute a, RuleMitreAttackMitigationAttribute b) => { return string.Compare(a.Label, b.Label); });

            Add("<hr>");
            Add("<h2 class='mt-4'>Mitigations</h2>");

            // CARDS
            Add("<div class='row'><div class='col-lg-12'>");
            Add("<div class='row row-cols-" + Enum.GetValues(typeof(MitreAttackMitigation)).Length + "'>");
            foreach (MitreAttackMitigation mainTechnique in Enum.GetValues(typeof(MitreAttackMitigation)))
            {
                Add("<div class='col'>");
                Add("<div class='card'>");
                Add("<div class='card-body'>");
                Add("<h5 class='card-title'>");
                var description = ReportHelper.GetEnumDescription(mainTechnique);
                Add(description);
                Add("</h5>");
                int num = 0;
                foreach (var l in keys)
                {
                    if (l.MainTechnique != mainTechnique)
                        continue;
                    num++;
                }
                if (num > 0)
                {
                    Add("<p class='card-text'>Mitigation did matched");
                    Add("</p>");
                }
                else
                {
                    Add("<p class='card-text'>No match</p>");
                }
                Add("</div>");
                Add("</div>");
                Add("</div>");
            }
            Add("</div>");
            Add("</div></div>");

            // tab header
            if (reference.Count > 0)
            {
                Add("<div class='row mt-4'><div class='col-lg-12'>");
                Add(@"<ul class=""nav nav-tabs d-none1"">");
                bool first = true;
                foreach (MitreAttackMitigation mainTechnique in Enum.GetValues(typeof(MitreAttackMitigation)))
                {
                    int num = 0;
                    foreach (var l in keys)
                    {
                        if (l.MainTechnique != mainTechnique)
                            continue;
                        num++;
                    }
                    if (num > 0)
                    {
                        Add("<li class='nav-item bg-light'>");
                        Add(@"<a class='nav-link");
                        if (first)
                        {
                            Add(" active");
                            first = false;
                        }
                        Add(@"' data-bs-toggle=""tab"" href=""#mitre");
                        Add(mainTechnique.ToString());
                        Add(Report.GenerationDate.ToFileTime().ToString());
                        Add(@""">");
                        var description = ReportHelper.GetEnumDescription(mainTechnique);
                        Add(description);
                        Add("</a>");
                        Add("</li>");
                    }
                }
                Add("</ul>");
                Add("</div></div>");


                // tab content
                Add("<div class='row'><div class='col-lg-12'>");
                Add(@"<div class=""tab-content"">");
                first = true;
                foreach (MitreAttackMitigation mainTechnique in Enum.GetValues(typeof(MitreAttackMitigation)))
                {
                    int num = 0;
                    foreach (var l in keys)
                    {
                        if (l.MainTechnique != mainTechnique)
                            continue;
                        num++;
                    }
                    if (num > 0)
                    {

                        Add(@"<div id=""mitre");
                        Add(mainTechnique.ToString());
                        Add(Report.GenerationDate.ToFileTime().ToString());
                        Add(@""" class=""tab-pane");
                        if (first)
                        {
                            Add(" active");
                            first = false;
                        }
                        Add(@""">");

                        Add("<div class='row'><div class='col-lg-12'>");
                        var description = ReportHelper.GetEnumDescription(mainTechnique);
                        Add("<p class='mt-2'><strong>" + description + "</strong></p>");

                        foreach (var l in keys)
                        {
                            if (l.MainTechnique != mainTechnique)
                                continue;
                            //title
                            Add("<p class='mt-2'><a href=");
                            Add(((RuleFrameworkReference)l).URL);
                            Add(">");
                            Add(((RuleFrameworkReference)l).Label);
                            Add("</a> [");
                            Add(reference[l].Count);
                            Add("]</p>");
                            GenerateAccordion("rulesmitre" + l.ID + l.SubID, () =>
                            {
                                reference[l].Sort((HealthCheckCloudDataRiskRule a, HealthCheckCloudDataRiskRule b) => { return -a.Points.CompareTo(b.Points); });
                                foreach (HealthCheckCloudDataRiskRule rule in reference[l])
                                {
                                    GenerateIndicatorPanelDetail("mitre" + l.ID + l.SubID, rule, "mitre" + l.ID + l.SubID);
                                }
                            });
                        }
                        Add("</div></div>");
                        Add("</div>");
                    }
                }
                Add("</div>");
                Add("</div></div>");
            }
        }

        #endregion


        private void GenerateTenantInformation()
        {
            AddAnchor("tenantinformation");

            AddParagraph("This section shows the main technical characteristics of the tenant.");

            AddBeginTable("Tenant information", true);
            AddHeaderText("Tenant Name");
            AddHeaderText("Tenant ID");
            AddHeaderText("Creation date");
            AddHeaderText("Region");
            AddBeginTableData();
            AddBeginRow();

            AddCellText(Report.TenantName);
            AddCellText(Report.TenantId);
            AddCellDate(Report.TenantCreation);
            AddCellText(Report.Region);
            AddEndRow();
            AddEndTable();

            GenerateSubSection("Business card");
            // todo: tenant branding 
            Add(@"<div class='card'>
  <div class='card-body'>
<h5 class='card-title'>");
            Add(Report.ProvisionDisplayName);
            Add(@"</h5>
    <p class='card-text'>");

            if (!string.IsNullOrEmpty(Report.ProvisionStreet))
                AddParagraph("Street: " + Report.ProvisionStreet);
            if (!string.IsNullOrEmpty(Report.ProvisionCity))
                AddParagraph("City: " + Report.ProvisionCity);
            if (!string.IsNullOrEmpty(Report.ProvisionPostalCode))
                AddParagraph("Postal Code: " + Report.ProvisionPostalCode);
            if (!string.IsNullOrEmpty(Report.ProvisionCountry))
                AddParagraph("Country: " + Report.ProvisionCountry);
            if (!string.IsNullOrEmpty(Report.ProvisionState))
                AddParagraph("State: " + Report.ProvisionState);
            if (!string.IsNullOrEmpty(Report.ProvisionTelephoneNumber))
                AddParagraph("Phone: " + Report.ProvisionTelephoneNumber);

            Add(@"</p>
  </div>
</div>");
            GenerateSubSection("Contacts information");
            AddBeginTable("ContactsInfo");
            AddHeaderText("Type");
            AddHeaderText("Contact");
            AddBeginTableData();
            if (Report.ProvisionMarketingNotificationEmails != null)
            {
                foreach (var contact in Report.ProvisionMarketingNotificationEmails)
                {
                    AddBeginRow();
                    AddCellText("Marketing notifications");
                    AddCellText(contact);
                    AddEndRow();

                }
            }
            if (Report.ProvisionTechnicalNotificationEmails != null)
            {
                foreach (var contact in Report.ProvisionTechnicalNotificationEmails)
                {
                    AddBeginRow();
                    AddCellText("Technical notifications");
                    AddCellText(contact);
                    AddEndRow();

                }
            }
            if (Report.ProvisionSecurityComplianceNotificationEmails != null)
            {
                foreach (var contact in Report.ProvisionSecurityComplianceNotificationEmails)
                {
                    AddBeginRow();
                    AddCellText("Security Compliance notifications");
                    AddCellText(contact);
                    AddEndRow();

                }
            }
            AddEndTable();

        }

        private void GenerateOnPremiseInformation()
        {
            AddParagraph("This section shows information about the local Active Directory domain.");
            GenerateSubSection("Synchronization information");
            AddBeginTable("DirSync information", true);
            AddHeaderText("DirectorySynchronizationStatus");
            AddHeaderText("LastDirSyncTime");
            AddHeaderText("LastPasswordSyncTime");
            AddHeaderText("DirSyncApplicationType");
            AddHeaderText("DirSyncClientMachineName");
            AddHeaderText("DirSyncClientVersion");
            AddHeaderText("DirSyncServiceAccount");
            AddBeginTableData();
            AddBeginRow();

            AddCellText(Report.ProvisionDirectorySynchronizationStatus);
            if (Report.ProvisionLastDirSyncTime != null)
                AddCellDate((DateTime)Report.ProvisionLastDirSyncTime);
            else
                AddCellText(null);
            if (Report.ProvisionLastPasswordSyncTime != null)
                AddCellDate((DateTime)Report.ProvisionLastPasswordSyncTime);
            else
                AddCellText(null);
            AddCellText(Report.ProvisionDirSyncApplicationType);
            AddCellText(Report.ProvisionDirSyncClientMachineName);
            AddCellText(Report.ProvisionDirSyncClientVersion);
            AddCellText(Report.ProvisionDirSyncServiceAccount);
            AddEndRow();
            AddEndTable();

            GenerateSubSection("Information about on premise domain");
            AddParagraph("This section displays potential information about the local Active Directory");
            if (string.IsNullOrEmpty(Report.OnPremiseDomainSid))
            {
                AddParagraph("The local SID couldn't be detected");
            }
            else
            {
                if (GetUrlCallbackDomain == null)
                {
                    AddParagraph("The local SID is: " + Report.OnPremiseDomainSid);
                }
                else
                {
                    string domainLink = GetUrlCallbackDomain(DomainKey.Create(null, Report.OnPremiseDomainSid, null), Report.OnPremiseDomainSid, null);
                    if (string.IsNullOrEmpty(domainLink))
                    {
                        AddParagraph("The local SID is: " + Report.OnPremiseDomainSid);
                    }
                    else
                    {

                        Add("<div class='row'><div class='col-lg-12'><p>");
                        AddEncoded("The local domain is: ");
                        Add(domainLink);
                        Add("</p></div></div>");
                    }
                    
                }
            }
        }

        class TenantInformation
        {
            public HealthCheckCloudDataForeignDomains TopDomain { get; set; }
            public HealthCheckCloudDataTenantInformation TenantInfo { get; set; }
            public int GuestsCount { get; set; }
            public int MemberCount { get; set; }
            public int TopTotal { get; set; }
            public int NumberOfDomains { get; set; }
        }



        Dictionary<string, TenantInformation> GenerateTenantInfo()
        {

            var dict = new Dictionary<string, TenantInformation>();
            foreach (var domain in Report.ForeignDomains)
            {
                if (string.IsNullOrEmpty(domain.TenantID))
                    continue;
                if (!dict.ContainsKey(domain.TenantID))
                {
                    dict[domain.TenantID] = new TenantInformation()
                    {
                        GuestsCount = domain.GuestsCount,
                        MemberCount = domain.MemberCount,
                        NumberOfDomains = 1,
                        TopDomain = domain,
                        TopTotal = domain.GuestsCount + domain.MemberCount,
                    };
                }
                else
                {
                    var d = dict[domain.TenantID];
                    d.GuestsCount += domain.GuestsCount;
                    d.MemberCount += domain.MemberCount;
                    d.NumberOfDomains++;
                    var TopTotal = domain.GuestsCount + domain.MemberCount;
                    if (d.TopTotal < TopTotal)
                    {
                        d.TopTotal = TopTotal;
                        d.TopDomain = domain;
                    }

                }
            }
            foreach (var tenant in Report.ExternalTenantInformation)
            {
                if (dict.ContainsKey(tenant.TenantID))
                {
                    dict[tenant.TenantID].TenantInfo = tenant;
                }
            }
            if (dict.ContainsKey("9cd80435-793b-4f48-844b-6b3f37d1c1f3"))
            {
                dict["9cd80435-793b-4f48-844b-6b3f37d1c1f3"].TenantInfo = new HealthCheckCloudDataTenantInformation
                {
                    Name = "+Personal Emails+",
                    TenantID = "9cd80435-793b-4f48-844b-6b3f37d1c1f3",
                };
            }
            return dict;
        }

        private void GenerateInternetPresenceInformation()
        {
            GenerateSubSection("DNS Domains registered for the tenant");
            AddParagraph("This section shows information about the DNS domains registered.");
            if (Report.Domains != null)
            {
                Report.Domains.Sort((a, b) => a.Name.CompareTo(b.Name));
                AddBeginTable("DNSDomains");
                AddHeaderText("Name");
                AddHeaderText("IsInitial");
                AddHeaderText("Authentication");
                AddHeaderText("Capabilities");
                AddHeaderText("Status");
                AddHeaderText("Verified by");
                AddBeginTableData();
                foreach (var domain in Report.Domains)
                {
                    AddBeginRow();
                    AddCellText(domain.Name);
                    AddCellText(domain.IsInitial.ToString());
                    AddCellText(domain.Authentication);
                    AddCellText(domain.Capabilities);
                    AddCellText(domain.Status);
                    AddCellText(domain.VerificationMethod);
                    AddEndRow();
                }
                AddEndTable();
            }

            GenerateSubSection("Internet networks registered for the tenant");
            AddParagraph("This section shows information about the Networks registered.");
            if (Report.NetworkPolicies != null)
            {
                AddBeginTable("DNSDomains");
                AddHeaderText("Name");
                AddHeaderText("Type");
                AddHeaderText("Definition");
                AddHeaderText("Trusted");
                AddHeaderText("ApplyToUnknownCountry");
                AddBeginTableData();
                foreach (var domain in Report.NetworkPolicies)
                {
                    AddBeginRow();
                    AddCellText(domain.Name);
                    AddCellText(domain.Type);
                    AddCellText(domain.Definition);
                    AddCellBool(domain.Trusted);
                    AddCellBool(domain.ApplyToUnknownCountry);
                    AddEndRow();
                }
                AddEndTable();
            }
        }

        private void GenerateExternalTenantsInformation()
        {
            Dictionary<string, TenantInformation> tenantInfo = null;
            if (Report.ForeignDomains != null)
                tenantInfo = GenerateTenantInfo();
            if (Report.CrossTenantPolicies != null)
            {
                GenerateSubSection("Cross tenants");
                AddParagraph("This section shows information about trusted tenants.");
                AddParagraph("This information is extracted from https://docs.microsoft.com/en-us/azure/active-directory/external-identities/cross-tenant-access-settings-b2b-direct-connect");

                if (Report.Domains != null)
                    Report.Domains.Sort((a, b) => a.Name.CompareTo(b.Name));
                AddBeginTable("CrossTenantPolicies");
                AddHeaderText("TenantId");
                AddHeaderText("Tenant Name");
                AddHeaderText("AllowB2BFrom");
                AddHeaderText("AllowB2BTo");
                AddHeaderText("AllowNativeFederationFrom");
                AddHeaderText("AllowNativeFederationTo");
                AddHeaderText("lastModified");
                AddBeginTableData();
                foreach (var domain in Report.CrossTenantPolicies)
                {
                    AddBeginRow();
                    AddCellText(domain.TenantId);
                    if (tenantInfo != null && tenantInfo.ContainsKey(domain.TenantId))
                    {
                        var ti = tenantInfo[domain.TenantId];

                        if (ti.TenantInfo != null && ti.TopDomain != null)
                        {
                            Add("<td class='text'>");
                            AddEncoded(ti.TenantInfo.Name);
                            AddBeginTooltip(true, true);
                            Add("<div class='text-left'>Domain: ");
                            AddEncoded(ti.TopDomain.Domain);
                            Add("</div>");
                            AddEndTooltip();
                            Add("</td>");
                        }
                        else if (ti.TenantInfo != null)
                        {
                            AddCellText(ti.TenantInfo.Name);
                        }
                        else if (ti.TopDomain != null)
                        {
                            AddCellText(ti.TopDomain.Domain);
                        }
                        else
                        {
                            AddCellText(null);
                        }
                    }
                    else
                    {
                        AddCellText(null);
                    }
                    AddCellBool(domain.AllowB2BFrom);
                    AddCellBool(domain.AllowB2BTo);
                    AddCellBool(domain.AllowNativeFederationFrom);
                    AddCellBool(domain.AllowNativeFederationTo);
                    AddCellText(domain.lastModified);
                    AddEndRow();
                }
                AddEndTable();
            }
            if (Report.ForeignDomains != null)
            {
                GenerateSubSection("External Tenant in use");

                AddBeginModal("tenant_modal", "List of domains used with this tenant",
                ShowModalType.XL);
                DescribeBegin();
                DescribeLabel("Tenant ID");
                DescribeValue("", "tenantId");
                DescribeEnd();

                Add("<h3>Domains</h3>");
                AddBeginTable("Application Permissions", id: "t_tenant_domain");
                AddHeaderText("Name", datafield: "Domain");
                AddHeaderText("GuestsCount", datafield: "GuestsCount");
                AddHeaderText("MemberCount", datafield: "MemberCount");
                AddHeaderText("Total", datafield: "MemberCount", dataformatter: "TotalDomains");
                AddBeginTableData();
                AddEndTable();
                AddEndModal();

                AddParagraph("This is the analysis of guests or external members per external tenants. Guests are allowed to connect and may be able to list the membership of all groups, thus reconstructing the list of all users.");
                Add("<div class='foreigntenantcontainer'>");
                AddBeginTable("Foreign Tenants");
                AddHeaderText("Name");
                AddHeaderText("Region");
                AddHeaderText("TenantID");
                AddHeaderText("Number of domains");
                AddHeaderText("GuestsCount");
                AddHeaderText("MemberCount");
                AddHeaderText("Total");
                AddBeginTableData();
                foreach (var domain in tenantInfo.Values.OrderByDescending(x => x.MemberCount + x.GuestsCount))
                {
                    AddBeginRow();
                    if (domain.TenantInfo != null && domain.TopDomain != null)
                    {
                        Add("<td class='text'>");
                        Add(@"<a class='data-pc-toggle-tenant' href=""#");
                        AddEncoded(domain.TenantInfo.TenantID);
                        Add(@""">");
                        AddEncoded(domain.TenantInfo.Name);
                        Add("</a>");
                        AddBeginTooltip(true, true);
                        Add("<div class='text-left'>Domain with most users: ");
                        AddEncoded(domain.TopDomain.Domain);
                        Add("</div>");
                        AddEndTooltip();
                        Add("</td>");
                    }
                    else if (domain.TenantInfo != null)
                    {
                        Add("<td class='text'>");
                        Add(@"<a class='data-pc-toggle-tenant' href=""#");
                        AddEncoded(domain.TenantInfo.TenantID);
                        Add(@""">");
                        AddEncoded(domain.TenantInfo.Name);
                        Add("</a>");
                        Add("</td>");
                    }
                    else if (domain.TopDomain != null && !string.IsNullOrEmpty(domain.TopDomain.TenantID))
                    {
                        Add("<td class='text'>");
                        Add(@"<a class='data-pc-toggle-tenant' href=""#");
                        AddEncoded(domain.TopDomain.TenantID);
                        Add(@""">");
                        AddEncoded(domain.TopDomain.Domain);
                        Add("</a>");
                        Add("</td>");
                    }
                    else if (domain.TopDomain != null)
                    {
                        AddCellText(domain.TopDomain.Domain);
                    }
                    else
                    {
                        AddCellText(null);
                    }
                    AddCellText(domain.TopDomain.Region);
                    AddCellText(domain.TopDomain.TenantID);
                    AddCellNum(domain.NumberOfDomains);
                    AddCellNum(domain.GuestsCount);
                    AddCellNum(domain.MemberCount);
                    AddCellNum(domain.GuestsCount + domain.MemberCount);
                    AddEndRow();
                }
                AddEndTable();
                Add("</div>");

                Add(@"<script type='application/json' data-pingcastle-selector='ForeignTenants'>");
                Add(JsonConvert.SerializeObject(Report.ForeignDomains));
                Add(@"</script>");
            }
        }

        private string GenerateModalAdminGroupIdFromGroupName(string groupname)
        {
            return "modal" + groupname.Replace(" ", "-").Replace("<", "");
        }

        private void GenerateAdminsInformation()
        {
            if (Report.Roles != null)
            {
                GenerateSubSection("Groups", "admingroups");
                AddParagraph("This section is focused on the groups which are critical for admin activities. If the report has been saved which the full details, each group can be zoomed with its members. If it is not the case, for privacy reasons, only general statistics are available.");
                AddBeginTable("Admin groups list");
                AddHeaderText("Group Name");
                AddHeaderText("Critical?", "Indicates if the group is considered as critical in term of damage capability");
                AddHeaderText("Nb Admins", "This is the number of user accounts member of this group");
                AddHeaderText("No MFA", "Accounts without MFA enabled or enforced");
                AddHeaderText("On premise accounts");
                AddHeaderText("Password Never Expires");
                AddHeaderText("LastPasswordChangeTimestamp");
                AddBeginTableData();

                Report.Roles.Sort((HealthCheckCloudDataRole a, HealthCheckCloudDataRole b)
                    =>
                {
                    int ret = (b.NumMembers > 0).CompareTo((a.NumMembers > 0));
                    if (ret == 0)
                        return String.Compare(a.Name, b.Name);
                    return ret;
                }
                );
                foreach (var group in Report.Roles)
                {
                    AddBeginRow();
                    if (group.members != null && group.members.Count > 0)
                    {
                        Add(@"<td class='text'><a data-bs-toggle=""modal"" href=""#");
                        Add(GenerateModalAdminGroupIdFromGroupName(group.ObjectId.ToString()));
                        Add(@""">");
                        AddEncoded(group.Name);
                        Add("</a></td>");
                    }
                    else
                    {
                        AddCellText(group.Name);
                    }
                    AddCellBool(dangerousRole.Contains(group.Name));
                    AddCellNum(group.NumMembers);
                    AddCellNum(group.NumNoMFA);
                    AddCellNum(group.members.Where(x => x.HasImmutableId).Count());
                    AddCellNum(group.members.Where(x => x.PasswordNeverExpires == true).Count());
                    AddCellNum(group.members.Where(x => x.LastPasswordChangeTimestamp != null && x.LastPasswordChangeTimestamp.Value.AddDays(90) < DateTime.Now).Count());
                    AddEndRow();
                }
                AddEndTable();
                foreach (var group in Report.Roles)
                {
                    if (group.members != null && group.members.Count > 0)
                    {
                        AddBeginModal(GenerateModalAdminGroupIdFromGroupName(group.ObjectId.ToString()), group.Name, ShowModalType.XL);
                        GenerateAdminGroupsDetail(group.members);
                        AddEndModal();
                    }
                }
            }
        }

        private void GenerateUsersInformation()
        {
            AddParagraph("This section gives information about the user accounts stored in AzureAD");
            GenerateSubSection("Account analysis", "useraccountanalysis");
            AddBeginTable("Account analysis list", true);
            AddHeaderText("Nb User Accounts");
            AddHeaderText("Nb User Guests");
            AddHeaderText("Nb User Members");
            AddHeaderText("Nb User External Members");
            AddHeaderText("Nb User Internal Members");
            AddHeaderText("Nb User Internal Members sync on premise");
            AddHeaderText("Nb User Internal Members Pure Azure");
            AddHeaderText("Password never expires");
            AddBeginTableData();
            AddBeginRow();
            AddCellNum(Report.NumberOfUsers);
            AddCellNum(Report.NumberofGuests);
            AddCellNum(Report.NumberofMembers);
            AddCellNum(Report.NumberofExternalMembers);
            AddCellNum(Report.NumberofInternalMembers);
            AddCellNum(Report.NumberofSyncInternalMembers);
            AddCellNum(Report.NumberofPureAureInternalMembers);
            AddCellNum(Report.UsersPasswordNeverExpires == null ? 0 : Report.UsersPasswordNeverExpires.Count);
            AddEndRow();
            AddEndTable();
            GenerateAccordion("usersaccordion",
                () =>
                {
                    if (Report.UsersPasswordNeverExpires != null && Report.UsersPasswordNeverExpires.Count > 0)
                    {
                        GenerateListAccountDetail("usersaccordion", "sectionneverexpires", "Objects with a password which never expires ", Report.UsersPasswordNeverExpires);
                    }
                });

            Add("<h2>Users ratio</h2>");
            Add("<div class='row'>");
            Add("<div class='col-lg-4'>");
            Add(@"<div class=""card"">
  <div class=""card-body"">
    <h5 class=""card-title"">Guest users (");
            Add(Report.NumberofGuests.ToString("#,##0"));
            Add(@") over all users (");
            Add(Report.NumberOfUsers.ToString("#,##0"));
            Add(@")</h5>
    ");
            AddPie(50, Report.NumberOfUsers, Report.NumberofGuests);
            Add(@"
  </div>
</div>");
            Add("</div>");
            Add("<div class='col-lg-4'>");
            Add(@"<div class=""card"">
  <div class=""card-body"">
    <h5 class=""card-title"">External members (");
            Add(Report.NumberofExternalMembers.ToString("#,##0"));
            Add(@") over all members (");
            Add(Report.NumberofMembers.ToString("#,##0"));
            Add(@")</h5>
    ");
            AddPie(50, Report.NumberofMembers, Report.NumberofExternalMembers);
            Add(@"
  </div>
</div>");
            Add("</div>");
            Add("<div class='col-lg-4'>");
            Add(@"<div class=""card"">
  <div class=""card-body"">
    <h5 class=""card-title"">Pure Azure member(");
            Add(Report.NumberofPureAureInternalMembers.ToString("#,##0"));
            Add(@") over all members (");
            Add(Report.NumberofMembers.ToString("#,##0"));
            Add(@")</h5>
    ");
            AddPie(50, Report.NumberofMembers, Report.NumberofPureAureInternalMembers);
            Add(@"
  </div>
</div>");
            Add("</div>");
            Add("</div>");

        }

        void GenerateListAccountDetail(string accordion, string id, string title, List<HealthCheckCloudDataUser> list)
        {
            if (list == null)
            {
                return;
            }
            GenerateAccordionDetailForDetail(id, accordion, title, list.Count, () =>
            {
                AddBeginTable("Account list");
                AddHeaderText("Name");
                AddHeaderText("Creation");
                AddHeaderText("Last logon");
                AddHeaderText("Object Id");
                AddBeginTableData();

                int number = 0;
                list.Sort((HealthCheckCloudDataUser a, HealthCheckCloudDataUser b)
                    =>
                {
                    return String.Compare(a.UserPrincipalName, b.UserPrincipalName);
                }
                    );
                foreach (var detail in list)
                {
                    AddBeginRow();
                    AddCellText(detail.UserPrincipalName);
                    AddCellText((detail.WhenCreated != null ? detail.WhenCreated.Value.ToString("u") : null));
                    AddCellText((detail.LastPasswordChangeTimestamp != null ? detail.LastPasswordChangeTimestamp.Value.ToString("u") : ""));

                    if (detail.ObjectId != null)
                        AddCellText(detail.ObjectId.ToString());
                    else
                        AddCellText(null);
                    AddEndRow();
                    number++;
                    if (number >= MaxNumberUsersInHtmlReport)
                    {
                        break;
                    }
                }
                AddEndTable(() =>
                {
                    if (number >= MaxNumberUsersInHtmlReport)
                    {
                        Add("<td colspan='");
                        Add(4);
                        Add("' class='text'>");
                        AddEncoded(string.Format(MaxNumberUsersInHtmlReportMessage, MaxNumberUsersInHtmlReport));
                        Add("</td>");
                    }
                });
            });
        }

        private void GenerateAdminGroupsDetail(List<HealthCheckCloudDataRoleMember> members)
        {
            if (members != null)
            {
                AddBeginTable("Admin groups detail");
                AddHeaderText("Display Name");
                AddHeaderText("Email");
                AddHeaderText("On premise account");
                AddHeaderText("When Created");
                AddHeaderText("Last Password Change");
                AddHeaderText("Password Never Expires");
                AddHeaderText("No MFA");
                AddHeaderText("Role Member Type");
                AddHeaderText("Status");
                AddHeaderText("Is Licensed");
                AddHeaderText("LastDirSyncTime");

                AddHeaderText("ObjectID");
                AddBeginTableData();
                members.Sort((HealthCheckCloudDataRoleMember a, HealthCheckCloudDataRoleMember b)
                    =>
                {
                    return String.Compare(a.DisplayName, b.DisplayName);
                }
                );
                foreach (var member in members)
                {

                    AddBeginRow();
                    AddCellText(member.DisplayName);
                    AddCellText(member.EmailAddress);
                    AddCellBool(member.HasImmutableId);
                    if (member.WhenCreated != null)
                        AddCellDate((DateTime)member.WhenCreated);
                    else
                        AddCellText(null);
                    if (member.LastPasswordChangeTimestamp != null)
                        AddCellDate((DateTime)member.LastPasswordChangeTimestamp);
                    else
                        AddCellText(null);
                    if (member.PasswordNeverExpires != null)
                        AddCellText(member.PasswordNeverExpires.ToString(), (bool)member.PasswordNeverExpires);
                    else
                        AddCellText(null);
                    AddCellText(member.MFAStatus == null || member.MFAStatus.Count == 0 ? "Unknown" : string.Join(",", member.MFAStatus.ToArray())); ;
                    AddCellText(member.RoleMemberType);
                    AddCellText(member.OverallProvisioningStatus);
                    AddCellText(member.IsLicensed.ToString());
                    if (member.LastDirSyncTime == null)
                        AddCellText(null);
                    else
                        AddCellDate((DateTime)member.LastDirSyncTime);
                    AddCellText(member.ObjectId.ToString());
                    AddEndRow();

                }
                AddEndTable();
            }
        }

        static string[] dangerousAppPermissions = new string[]
        {
            "Mail.Read",
            "Mail.ReadWrite",
            "Mail.Send",
            "Contacts.Read",
            "Contacts.ReadWrite",
            "MailboxSettings.Read",
            "MailboxSettings.ReadWrite",
            "People.Read.All",
            "Files.Read.All",
            "Files.ReadWrite.All",
            "Notes.Read.All",
            "Notes.ReadWrite.All",
            "Application.ReadWrite.All",
            "Directory.ReadWrite.All",
            "Domain.ReadWrite.All",
            "EduRoster.ReadWrite.All",
            "Group.ReadWrite.All",
            "Member.Read.Hidden",
            "RoleManagement.ReadWrite.Directory",
            "User.ReadWrite.All",
            "User.ManageCreds.All",
        };

        static string[] dangerousDelegatedPermissions = new string[]
        {
            "Application.Read",
            "Mail.Read",
            "Mail.ReadWrite",
            "Mail.ReadWrite.All",
            "Mail.Read.All",
            "Mail.Read.Shared",
            "Mail.Send",
            "Mail.Send.All",
            "Mail.Send.Shared",
            "MailboxSettings.Read",
            "MailboxSettings.ReadWrite",
            "Contacts.Read",
            "Contacts.Read.Shared",
            "Contacts.ReadWrite",
            "Contacts.ReadWrite.Shared",
            "People.Read",
            "People.Read.All",
            "Files.Read",
            "Files.Read.All",
            "Files.ReadWrite",
            "Files.ReadWrite.All",
            "Notes.Read",
            "Notes.ReadWrite",
            "Notes.Read.All",
            "Notes.ReadWrite.All",
            "Directory.AccessAsUser.All",
            "Application.Read.All",
            "Application.ReadWrite.All",
            "AppRoleAssignment.ReadWrite.All",
            "Directory.ReadWrite.All",
            "EduRoster.ReadWrite",
            "Group.ReadWrite.All",
            "Member.Read.Hidden",
            "RoleManagement.ReadWrite.Directory",
            "RoleManagementPolicy.ReadWrite.Directory",
            "User.ReadWrite",
            "User.ReadWrite.All"
        };

        static string[] dangerousRole = new string[]
        {
            "Authentication Administrator",
            "Global Administrator",
            "Privileged Authentication Administrator",
            "Helpdesk Administrator",
            "User Administrator",
            "Password Admin",
            "Company Administrator",
        };

        bool IsApplicationPermissionDangerous(HealthCheckCloudDataApplicationRoleAssignedTo permission)
        {
            return dangerousAppPermissions.Contains(permission.permission);
        }
        bool IsDelegatedPermissionDangerous(HealthCheckCloudDataApplicationOAuth2PermissionGrant permission)
        {
            return dangerousDelegatedPermissions.Contains(permission.permission);
        }

        bool IsRoleDangerous(HealthCheckCloudDataApplicationMemberOf permission)
        {
            return !string.IsNullOrEmpty(permission.roleTemplateId) && dangerousRole.Contains(permission.displayName);
        }

        private void GenerateApplicationInformation()
        {
            if (Report.Applications == null || Report.Applications.Count == 0)
                return;


            AddBeginModal("application_modal", "",
                ShowModalType.XL);
            DescribeBegin();
            DescribeLabel("Object ID");
            DescribeValue("", "objectId");
            DescribeLabel("App ID");
            DescribeValue("", "appId");
            DescribeLabel("App Display name");
            DescribeValue("", "displayname");
            DescribeLabel("Tenant Owner");
            DescribeValue("", "tenantowner");
            DescribeEnd();

            Add("<h3>Application Permissions</h3>");
            AddBeginTable("Application Permissions", id: "t_app_app");
            AddHeaderText("resourceDisplayName", datafield: "resourceDisplayName");
            AddHeaderText("resourceId", datafield: "resourceId");
            AddHeaderText("permission", datafield: "permission", dataformatter: "permissionFormatter");
            AddHeaderText("Is Critical", datafield: "permission", dataformatter: "dangerousAppPermission");
            AddBeginTableData();
            AddEndTable();

            Add("<h3>Delegated Permissions</h3>");
            AddBeginTable("Delegated Permissions", id: "t_app_delegated");
            AddHeaderText("consentType", datafield: "consentType");
            AddHeaderText("principalId", datafield: "principalId", dataformatter: "delegatedPrincipal");
            AddHeaderText("resourceId", datafield: "resourceId");
            AddHeaderText("scope", datafield: "permission", dataformatter: "permissionFormatter");
            AddHeaderText("Is Critical", datafield: "permission", dataformatter: "dangerousDelegatedPermission");
            AddBeginTableData();

            AddEndTable();

            Add("<h3>MemberOf</h3>");
            AddBeginTable("Application is Member Of", id: "t_app_memberof");
            AddHeaderText("displayName", datafield: "displayName", dataformatter: "azureRole");
            AddHeaderText("roleTemplateId", datafield: "roleTemplateId");
            AddBeginTableData();
            AddEndTable();

            AddEndModal();


            Add("<h3>All applications</h3>");
            AddParagraph("Here is a list of the application defined on AzureAD.");
            Add("<div class='appcontainer'>");
            AddBeginTable("Applications detail");
            AddHeaderText("Display Name");
            AddHeaderText("External App");
            AddHeaderText("Application Permissions");
            AddHeaderText("Critical?", "Determine if there is critical application permissions");
            AddHeaderText("Delegated Permissions");
            AddHeaderText("Critical?", "Determine if there is critical delegated permissions");
            AddHeaderText("Roles", "The number of all roles, including native and custom one");
            AddHeaderText("Critical?", "Determine if there is critical roles");
            AddHeaderText("Azure Role", "The number of Azure native roles");
            AddBeginTableData();
            var k2 = Report.Applications.
                Where(x => x.ApplicationPermissions.Count > 0 || x.DelegatedPermissions.Count > 0 || x.MemberOf.Count > 0);
            foreach (var app in k2)
            {
                AddBeginRow();
                Add(@"<td class='text'><a class='data-pc-toggle-app' href=""#");
                AddEncoded(app.objectId);
                Add(@""">");
                if (!string.IsNullOrEmpty(app.appDisplayName))
                    AddEncoded(app.appDisplayName);
                else
                    AddEncoded("AppID_" + app.appId);
                Add("</a></td>");
                AddCellBool(app.appOwnerTenantId != Report.TenantId);
                AddCellNum(app.ApplicationPermissions.Count);
                AddCellBool(app.ApplicationPermissions.Where(x => IsApplicationPermissionDangerous(x)).Any());
                AddCellNum(app.DelegatedPermissions.Count);
                AddCellBool(app.DelegatedPermissions.Where(x => IsDelegatedPermissionDangerous(x)).Any());
                //app.DelegatedPermissions.Where(x => x.
                AddCellNum(app.MemberOf.Count);
                AddCellNum(app.MemberOf.Where(x => IsRoleDangerous(x)).Count());
                AddCellNum(app.MemberOf.Where(x => !string.IsNullOrEmpty(x.roleTemplateId)).Count());
                AddEndRow();

            }
            AddEndTable();
            Add("</div>");
            Add(@"<script type='application/json' data-pingcastle-selector='App'>");
            Add(JsonConvert.SerializeObject(Report.Applications));
            Add(@"</script>");
            Add(@"<script type='application/json' data-pingcastle-selector='dangerousAppPermissions'>");
            Add(JsonConvert.SerializeObject(dangerousAppPermissions));
            Add(@"</script>");
            Add(@"<script type='application/json' data-pingcastle-selector='dangerousDelegatedPermissions'>");
            Add(JsonConvert.SerializeObject(dangerousDelegatedPermissions));
            Add(@"</script>");

            Add("<h3>External tenant usage</h3>");
            AddParagraph("This is the list of external tenant having least at an application with a role");
            Add("<div class='appcontainer foreigntenantcontainer'>");
            AddBeginTable("External Applications");
            AddHeaderText("Tenant ID");
            AddHeaderText("Tenant Name");
            AddHeaderText("App example");
            AddHeaderText("Count");
            AddBeginTableData();
            var k = Report.Applications.Where(x => !string.IsNullOrEmpty(x.appOwnerTenantId) && x.appOwnerTenantId != Report.TenantId)
                .Where(x => x.ApplicationPermissions.Count > 0 || x.DelegatedPermissions.Count > 0 || x.MemberOf.Count > 0)
                .GroupBy(x => x.appOwnerTenantId)
                .Select(x => new { tenantId = x.Key, count = x.Count(), app = x.First() })
                .OrderBy(x => x.tenantId).ToList();

            Dictionary<string, TenantInformation> tenantInfo = null;
            if (Report.ForeignDomains != null)
                tenantInfo = GenerateTenantInfo();

            foreach (var t in k)
            {

                AddBeginRow();
                AddCellText(t.tenantId);
                if (tenantInfo != null && tenantInfo.ContainsKey(t.tenantId))
                {
                    var domain = tenantInfo[t.tenantId];
                    if (domain.TenantInfo != null && domain.TopDomain != null)
                    {
                        Add("<td class='text'>");
                        Add(@"<a class='data-pc-toggle-tenant' href=""#");
                        AddEncoded(domain.TenantInfo.TenantID);
                        Add(@""">");
                        AddEncoded(domain.TenantInfo.Name);
                        Add("</a>");
                        AddBeginTooltip(true, true);
                        Add("<div class='text-left'>Domain with most users: ");
                        AddEncoded(domain.TopDomain.Domain);
                        Add("</div>");
                        AddEndTooltip();
                        Add("</td>");
                    }
                    else if (domain.TenantInfo != null)
                    {
                        Add("<td class='text'>");
                        Add(@"<a class='data-pc-toggle-tenant' href=""#");
                        AddEncoded(domain.TenantInfo.TenantID);
                        Add(@""">");
                        AddEncoded(domain.TenantInfo.Name);
                        Add("</a>");
                        Add("</td>");
                    }
                    else if (domain.TopDomain != null && !string.IsNullOrEmpty(domain.TopDomain.TenantID))
                    {
                        Add("<td class='text'>");
                        Add(@"<a class='data-pc-toggle-tenant' href=""#");
                        AddEncoded(domain.TopDomain.TenantID);
                        Add(@""">");
                        AddEncoded(domain.TopDomain.Domain);
                        Add("</a>");
                        Add("</td>");
                    }
                    else if (domain.TopDomain != null)
                    {
                        AddCellText(domain.TopDomain.Domain);
                    }
                    else
                    {
                        AddCellText(null);
                    }
                }
                else
                {
                    AddCellText(null);
                }
                Add(@"<td class='text'><a class='data-pc-toggle-app' href=""#");
                AddEncoded(t.app.objectId);
                Add(@""">");
                if (!string.IsNullOrEmpty(t.app.appDisplayName))
                    AddEncoded(t.app.appDisplayName);
                else
                    AddEncoded("AppID_" + t.app.appId);
                Add("</a></td>");
                AddCellNum(t.count);
                AddEndRow();
            }
            AddEndTable();
            Add("</div>");
        }

        private void GenerateOutlookOnlineInformation()
        {
            if (Report.ForwardingMailboxes != null)
            {
                Add("<h3>Email forward</h3>");
                AddParagraph("This is the list of mailbox with a forward setting targetting a mailbox inside or outside of this tenant");
                AddBeginTable("Forward mailboxes");
                AddHeaderText("Mailbox");
                AddHeaderText("Destination");
                AddHeaderText("External");
                AddBeginTableData();
                foreach (var forward in Report.ForwardingMailboxes)
                {
                    AddBeginRow();
                    AddCellText(forward.PrimarySmtpAddress);
                    AddCellText(forward.ForwardingSmtpAddress);
                    var ma = new MailAddress(forward.ForwardingSmtpAddress);
                    bool external = true;
                    if (Report.Domains != null && Report.Domains.Where(x => x.Name == ma.Host).Any())
                    {
                        external = false;
                    }
                    AddCellBool(external);
                    AddEndRow();
                }
                AddEndTable();
            }
        }

    }
}

