//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Cloud.Data;
using PingCastle.Data;
using PingCastle.Graph.Database;
using PingCastle.Healthcheck;
using PingCastle.Rules;
using PingCastle.template;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;

namespace PingCastle.Report
{
    public class ReportHealthCheckSingle : ReportRiskControls<HealthcheckData>, IPingCastleReportUser<HealthcheckData>
    {

        protected HealthcheckData Report;
        public static int MaxNumberUsersInHtmlReport = 100;
        public static string MaxNumberUsersInHtmlReportMessage = "Output limited to {0} items - go to the advanced menu before running the report or add \"--no-enum-limit\" to remove that limit";
        protected ADHealthCheckingLicense _license;

        public string GenerateReportFile(HealthcheckData report, ADHealthCheckingLicense license, string filename)
        {
            Report = report;
            _license = license;
            report.InitializeReportingData();
            ReportID = GenerateUniqueID(report);
            Brand(license);
            return GenerateReportFile(filename);
        }

        private string GenerateUniqueID(IPingCastleReport report)
        {
            var s = report.Domain.DomainSID.Split('-');
            return GenerateUniqueID(report.Domain.DomainName, long.Parse(s[s.Length - 1]));
        }

        public string GenerateRawContent(HealthcheckData report, ADHealthCheckingLicense aDHealthCheckingLicense)
        {
            Report = report;
            _license = aDHealthCheckingLicense;
            AdjustReportIfNeeded();
            report.InitializeReportingData();
            sb.Length = 0;
            GenerateContent();
            return sb.ToString();
        }

        public string GenerateRawContent(HealthcheckData report)
        {
            return GenerateRawContent(report, null);
        }

        void AdjustReportIfNeeded()
        {
            if (!_license.IsBasic())
            {
                if (_license.CustomerNotice != null && _license.CustomerNotice.StartsWith("Free "))
                {
                    int count = Report.RiskRules.Count;
                    Random rnd = new Random();
                    for (int i = 0; i < count / 3; i++)
                    {
                        Report.RiskRules.RemoveAt(rnd.Next(Report.RiskRules.Count));
                    }
                    RuleSet<HealthcheckData>.ReComputeTotals(Report, Report.RiskRules.ConvertAll(x => x));
                }
            }
        }

        protected override void GenerateTitleInformation()
        {
            AddEncoded(Report.DomainFQDN);
            Add(" PingCastle ");
            Add(Report.GenerationDate.ToString("yyyy-MM-dd"));
        }


        protected override void ReferenceJSAndCSS()
        {
            AddStyle(TemplateManager.LoadReportRiskControlsCss());
            AddStyle(TemplateManager.LoadVisCss());
            AddStyle(TemplateManager.LoadReportCompromiseGraphCss());
            AddScript(TemplateManager.LoadVisJs());
            AddScript(TemplateManager.LoadReportCompromiseGraphJs());
            if (!_license.IsBasic())
            {
                AddScript(TemplateManager.LoadTableExportJs());
                AddScript(TemplateManager.LoadBootstrapTableExportJs());
            }
        }

        protected override void GenerateBodyInformation()
        {
            GenerateNavigation("HealthCheck report", Report.DomainFQDN, Report.GenerationDate);
            GenerateAbout();
            Add(@"
<div id=""wrapper"" class=""container well"">
	<noscript>
		<div class=""alert alert-warning"">
			<p>PingCastle reports work best with Javascript enabled.</p>
		</div>
	</noscript>
<div class=""row""><div class=""col-lg-12""><h1>");
            Add(Report.DomainFQDN);
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
            if (Report.WinTrustLevel != 0)
            {
                Add(@"<br>You are not using a supported version of PingCastle.");
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

        void AddHiddenValue(string name, string value)
        {
            Add("<input type='hidden' name='");
            AddEncoded(name);
            Add("' value='");
            AddEncoded(value);
            Add("'>");
        }


        protected void AddBenchmarkSection()
        {
            Add(@"
<div class=""modal"" tabindex=""-1"" role=""dialog"" id=""privacyNoticeStatistics"" >
  <div class=""modal-dialog"" role=""document"">
    <div class=""modal-content"">
      <div class=""modal-header"">
        <h4 class=""modal-title"">Privacy notice</h4>
        <button type=""button"" class=""btn-close"" data-bs-dismiss=""modal"" aria-label=""Close""></button>
      </div>
      <div class=""modal-body"">
        <p>To produce the statistics page, PingCastle will collect anonymous information in order to build this database.</p>
        <p>The information collected depends on the license level.</p>
        <p>Information collected:</p>
<ul>
<li>IP Address<br><span class='text-muted'><small>The goal is to compute country statistics and provide protection against database poisoning.</small></span></li>
<li>for the free license, the hash of the domain FQDN combined with the SID of the domain<br><span class='text-muted'><small>The goal is to compute the number of domains reported, without duplicates. The SID act as a salt to prohibit retrieving the original data by bruteforce.</small></span></li>
<li>Report generation date<br><span class='text-muted'><small>This is to remove duplicates.</small></span></li>
<li>The number of active users & active computers<br><span class='text-muted'><small>This is to compare with similar domain size.</small></span></li>
<li>The domain score and maturity level<br><span class='text-muted'><small>This is to compare with similar domain.</small></span></li>
<li>Rules ID that matched<br><span class='text-muted'><small>This is to present expected or non expected rules.</small></span></li>
<li>the license<br><span class='text-muted'><small>This allows licensed customer to not transmit their domain identifier.</small></span></li>
</ul>
<p>Informations not listed here are not sent to PingCastle</p>
      </div>
      <div class=""modal-footer"">
        <button type=""button"" class=""btn btn-secondary"" data-bs-dismiss=""modal"">Close</button>
      </div>
    </div>
  </div>
</div>
");


            var d = ReportBenchmark.GetData(Report, _license);
            Add(@"<form class='d-print-none' action='");
            Add(ReportBenchmark.GetDestination());
            Add("' method='POST'>");

            foreach (var item in d)
            {
                AddHiddenValue(item.Key, item.Value);
            }
            Add(@"<button type='submit' class='btn btn-default'>Compare with statistics</button></form>");
            AddParagraph("<a href='#' data-bs-toggle='modal' data-bs-target='#privacyNoticeStatistics' class='d-print-none'>Privacy notice</a>");
        }

        protected void GenerateContent()
        {
            if (Report.version >= new Version(3, 0) && !_license.IsBasic())
            {
                if (!Report.IntegrityVerified)
                {
                    Add(@"<div class=""alert alert-warning""><p>PingCastle has detected that the report has been modified before being uploaded to the application.</p></div>");
                }
            }
            GenerateSection("Active Directory Indicators", () =>
            {
                AddParagraph("This section focuses on the core security indicators.<br>Locate the sub-process determining the score and fix some rules in that area to get a score improvement.");
                GenerateIndicators(Report, Report.AllRiskRules, AddBenchmarkSection);
                GenerateRiskModelPanel(Report.RiskRules);
            });

            GenerateSection("Maturity Level", GenerateMaturityInformation);
            GenerateSection("MITRE ATT&CK&#174;", GenerateMitreAttackInformation);

            GenerateSection("Stale Objects", () =>
            {
                GenerateSubIndicatorHeader("Stale Objects", Report.GlobalScore, Report.StaleObjectsScore, "It is about operations related to user or computer objects");
                GenerateIndicatorPanel("DetailStale", "Stale Objects rule details", RiskRuleCategory.StaleObjects, Report.RiskRules, Report.applicableRules);
            });
            GenerateSection("Privileged Accounts", () =>
            {
                GenerateSubIndicatorHeader("Privileged Accounts", Report.GlobalScore, Report.PrivilegiedGroupScore, "It is about administrators of the Active Directory");
                GenerateIndicatorPanel("DetailPrivileged", "Privileged Accounts rule details", RiskRuleCategory.PrivilegedAccounts, Report.RiskRules, Report.applicableRules);
            });
            GenerateSection("Trusts", () =>
            {
                GenerateSubIndicatorHeader("Trusts", Report.GlobalScore, Report.TrustScore, "It is about links between two Active Directories");
                GenerateIndicatorPanel("DetailTrusts", "Trusts rule details", RiskRuleCategory.Trusts, Report.RiskRules, Report.applicableRules);
            });
            GenerateSection("Anomalies analysis", () =>
            {
                GenerateSubIndicatorHeader("Anomalies", Report.GlobalScore, Report.AnomalyScore, "It is about specific security control points");
                GenerateIndicatorPanel("DetailAnomalies", "Anomalies rule details", RiskRuleCategory.Anomalies, Report.RiskRules, Report.applicableRules);
            });
            GenerateSection("Domain Information", GenerateDomainInformation);
            GenerateSection("User Information", GenerateUserInformation);
            GenerateSection("Computer Information", GenerateComputerInformation);
            GenerateSection("Admin Groups", GenerateAdminGroupsInformation);
            GenerateSection("Control Paths Analysis", GenerateCompromissionGraphInformation);
            GenerateSection("Trusts details", GenerateTrustInformation);
            GenerateSection("PKI", GeneratePKIDetail);
            GenerateSection("Infrastructure", GenerateInfrastructureDetail);
            GenerateSection("Anomalies", GenerateAnomalyDetail);
            GenerateSection("Password Policies", GeneratePasswordPoliciesDetail);
            GenerateSection("GPO", GenerateGPODetail);
        }

        protected override void GenerateFooterInformation()
        {
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
                        Report.RiskRules.Sort((HealthcheckRiskRule a, HealthcheckRiskRule b)
                            =>
                        {
                            return -a.Points.CompareTo(b.Points);
                        }
                        );
                        foreach (HealthcheckRiskRule rule in Report.RiskRules)
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
                var hcrule = RuleSet<HealthcheckData>.GetRuleFromID(rule.RiskId);
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
            var reference = new Dictionary<RuleMitreAttackTechniqueAttribute, List<HealthcheckRiskRule>>();
            foreach (var rule in Report.RiskRules)
            {
                var hcrule = RuleSet<HealthcheckData>.GetRuleFromID(rule.RiskId);
                if (hcrule == null)
                {
                    continue;
                }
                object[] frameworks = hcrule.GetType().GetCustomAttributes(typeof(RuleMitreAttackTechniqueAttribute), true);
                foreach (RuleMitreAttackTechniqueAttribute f in frameworks)
                {
                    if (!reference.ContainsKey(f))
                    {
                        reference[f] = new List<HealthcheckRiskRule>();
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
                                reference[l].Sort((HealthcheckRiskRule a, HealthcheckRiskRule b) => { return -a.Points.CompareTo(b.Points); });
                                foreach (HealthcheckRiskRule rule in reference[l])
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
            var reference = new Dictionary<RuleMitreAttackMitigationAttribute, List<HealthcheckRiskRule>>();
            int notcovered = 0;
            foreach (var rule in Report.RiskRules)
            {
                var hcrule = RuleSet<HealthcheckData>.GetRuleFromID(rule.RiskId);
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
                        reference[f] = new List<HealthcheckRiskRule>();
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
                                reference[l].Sort((HealthcheckRiskRule a, HealthcheckRiskRule b) => { return -a.Points.CompareTo(b.Points); });
                                foreach (HealthcheckRiskRule rule in reference[l])
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

        #region domain info
        protected void GenerateDomainInformation()
        {
            bool checkRecycleBin = Report.version >= new Version(2, 7, 0, 0);
            AddAnchor("domaininformation");

            AddParagraph("This section shows the main technical characteristics of the domain.");

            AddBeginTable("Domain information", true);
            AddHeaderText("Domain");
            AddHeaderText("Netbios Name");
            AddHeaderText("Domain Functional Level");
            AddHeaderText("Forest Functional Level");
            AddHeaderText("Creation date");
            AddHeaderText("DC count");
            AddHeaderText("Schema version");
            if (checkRecycleBin)
            {
                AddHeaderText(@"Recycle Bin enabled");
            }
            AddBeginTableData();
            AddBeginRow();
            AddCellText(Report.DomainFQDN);
            AddCellText(Report.NetBIOSName);
            AddCellText(ReportHelper.DecodeDomainFunctionalLevel(Report.DomainFunctionalLevel));
            AddCellText(ReportHelper.DecodeForestFunctionalLevel(Report.ForestFunctionalLevel));
            AddCellDate(Report.DomainCreation);
            AddCellNum(Report.NumberOfDC);
            AddCellText(ReportHelper.GetSchemaVersion(Report.SchemaVersion));
            if (checkRecycleBin)
            {
                if (Report.IsRecycleBinEnabled)
                {
                    AddCellText("TRUE");
                }
                else
                {
                    AddCellText("FALSE", true);
                }
            }
            AddEndRow();
            AddEndTable();

            if (Report.version >= new Version(2, 10, 1))
            {
                GenerateSubSection("Azure AD Configuration", "azureAD");
                if (string.IsNullOrEmpty(Report.AzureADName))
                {
                    AddParagraph("No Azure AD configuration has been found in this domain");
                }
                else
                {
                    AddParagraph(@"Here is the Azure AD configuration that has been found in the domain");

                    AddBeginTable("Azure AD information", true);
                    AddHeaderText("Tenant name");
                    AddHeaderText("Tenant id");
                    AddHeaderText("Kerberos Enabled");
                    AddBeginTableData();
                    AddBeginRow();
                    Add(@"<td class='text'>");
                    string html = string.Empty;
                    if (GetUrlCallbackAzureAD != null)
                    {
                        html = GetUrlCallbackAzureAD(AzureADKey.Create(Report.AzureADName, Report.AzureADId), Report.AzureADName, null);
                    }
                    if (string.IsNullOrEmpty(html))
                    {
                        AddEncoded(Report.AzureADName);
                        AddBeginTooltip(html: true);
                        Add("TenantID: ");
                        AddEncoded(Report.AzureADId);
                        AddEndTooltip();
                    }
                    else
                    {
                        Add(html);
                    }
                    Add(@"</td>");

                    AddCellText(Report.AzureADId);
                    AddCellText(string.IsNullOrEmpty(Report.AzureADKerberosSid) ? "FALSE" : "TRUE");
                    AddEndRow();
                    AddEndTable();
                }
            }
        }

        #endregion domain info

        #region user info

        void AddAccountCheckHeader(bool computerView)
        {
            AddHeaderText("Nb Enabled", "Indicates the number of accounts not set as disabled.");
            AddHeaderText("Nb Disabled", "Indicates the number of accounts set as disabled.");
            AddHeaderText("Nb Active", "Indicates the number of enabled accounts where at least one logon occurred in the last 6 months.");
            AddHeaderText("Nb Inactive", "Indicates the number of enabled accounts without any logon during the last 6 months.");
            if (!computerView)
            {
                AddHeaderText("Nb Locked", "Indicates the number of enabled accounts set as locked.");
                AddHeaderText("Nb pwd never Expire", "Indicates the number of enabled accounts which have a password which never expires.");
            }
            AddHeaderText("Nb SidHistory", "Indicates the number of enabled accounts having the attribute SIDHistory set. This attributes indicates a foreign origin.");
            AddHeaderText("Nb Bad PrimaryGroup", "Indicates the number of enabled accounts whose group, set as primary, is not the default one.");
            if (!computerView)
            {
                AddHeaderText("Nb Password not Req.", "Indicates the number of enabled accounts which have a flag set in useraccountcontrol allowing empty passwords.");
                AddHeaderText("Nb Des enabled.", "Indicates the number of enabled accounts allowing the unsafe DES algorithm for authentication.");
            }
            AddHeaderText("Nb unconstrained delegations", "Indicates the number of enabled accounts having been granted the right to impersonate any users without any restrictions. PingCastle checks if the flag TRUSTED_FOR_DELEGATION is present in the useraccountcontrol attribute.");
            AddHeaderText("Nb Reversible password", "Indicates the number of enabled accounts whose password can be retrieved in clear text using hacking tools.");
        }

        protected void GenerateUserInformation()
        {
            AddParagraph("This section gives information about the user accounts stored in the Active Directory");
            if (Report.ListHoneyPot != null && Report.ListHoneyPot.Count > 0)
            {
                GenerateSubSection("Honey Pot", "honeypot");
                AddParagraph("A honey pot has been configured. It is used to generate fake security issues that are heavily monitored and that a hacker will spot using security tools like PingCastle. By enabling this feature, all the accounts listed below will not be evaluated with PingCastle rules.");
                GenerateAccordion("honeypotaccordion", () => GenerateListAccountDetail("honeypotaccordion", "honeypotid", "Honey pot accounts", Report.ListHoneyPot));
            }
            GenerateSubSection("Account analysis", "useraccountanalysis");
            AddBeginTable("Account analysis list", true);
            AddHeaderText("Nb User Accounts");
            AddAccountCheckHeader(false);
            AddBeginTableData();
            AddBeginRow();
            AddCellNum(Report.UserAccountData.Number);
            AddCellNum(Report.UserAccountData.NumberEnabled);
            AddCellNum(Report.UserAccountData.NumberDisabled);
            AddCellNum(Report.UserAccountData.NumberActive);
            SectionList("usersaccordion", "sectioninactiveuser", Report.UserAccountData.NumberInactive, Report.UserAccountData.ListInactive);
            SectionList("usersaccordion", "sectionlockeduser", Report.UserAccountData.NumberLocked, Report.UserAccountData.ListLocked);
            SectionList("usersaccordion", "sectionneverexpiresuser", Report.UserAccountData.NumberPwdNeverExpires, Report.UserAccountData.ListPwdNeverExpires);
            SectionList("usersaccordion", "sectionsidhistoryuser", Report.UserAccountData.NumberSidHistory, Report.UserAccountData.ListSidHistory);
            SectionList("usersaccordion", "sectionbadprimarygroupuser", Report.UserAccountData.NumberBadPrimaryGroup, Report.UserAccountData.ListBadPrimaryGroup);
            SectionList("usersaccordion", "sectionpwdnotrequireduser", Report.UserAccountData.NumberPwdNotRequired, Report.UserAccountData.ListPwdNotRequired);
            SectionList("usersaccordion", "sectiondesenableduser", Report.UserAccountData.NumberDesEnabled, Report.UserAccountData.ListDesEnabled);
            SectionList("usersaccordion", "sectiontrusteddelegationuser", Report.UserAccountData.NumberTrustedToAuthenticateForDelegation, Report.UserAccountData.ListTrustedToAuthenticateForDelegation);
            SectionList("usersaccordion", "sectionreversiblenuser", Report.UserAccountData.NumberReversibleEncryption, Report.UserAccountData.ListReversibleEncryption);
            AddEndRow();
            AddEndTable();
            GenerateListAccount(Report.UserAccountData, "user", "usersaccordion");
            if (Report.PasswordDistribution != null && Report.PasswordDistribution.Count > 0)
            {
                GenerateSubSection("Password Age Distribution", "passworddistribution");
                if (_license.IsBasic())
                {
                    AddParagraph("This feature is reserved for customers who have <a href='https://www.pingcastle.com/services/'>purchased a license</a>");
                }
                else
                {
                    AddParagraph("Here is the distribution where the password has been changed for the last time. Only enabled user accounts are analyzed (no guest account for example).");
                    AddDistributionChart(Report.PasswordDistribution.Select(x => new DistributionItem { HigherBound = x.HigherBound, Value = x.Value }), "general");
                }
            }
            GenerateDomainSIDHistoryList(Report.UserAccountData);
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
                    if (data.ListNotAesEnabled != null && data.ListNotAesEnabled.Count > 0)
                    {
                        GenerateListAccountDetail(accordion, "sectionnotaesenabled" + root, "Objects where AES usage with kerberos may be cause issues", data.ListNotAesEnabled,
                            tooltip: "Accounts are listed if 1) no password changed occured after the first DC Win 2008 install to initate AES secrets or 2) they have a SPN and the account is not flaged to use AES for encryption with msDS-SupportedEncryptionTypes");
                    }
                    if (data.ListTrustedToAuthenticateForDelegation != null && data.ListTrustedToAuthenticateForDelegation.Count > 0)
                    {
                        GenerateListAccountDetail(accordion, "sectiontrusteddelegation" + root, "Objects trusted to authenticate for delegation ", data.ListTrustedToAuthenticateForDelegation);
                    }
                    if (data.ListReversibleEncryption != null && data.ListReversibleEncryption.Count > 0)
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

        void SectionList(string accordion, string section, int value, IList<HealthcheckAccountDetailData> list)
        {
            if (value > 0 && list != null && list.Count > 0)
            {
                Add(@"<td class='num'><a data-bs-toggle=""collapse"" href=""#");
                Add(section);
                Add(@""" data-parent=""#");
                Add(accordion);
                Add(@""">");
                Add(value);
                Add(@"</a></td>");
            }
            else
            {
                AddCellNum(value);
            }
        }

        void GenerateListAccountDetail(string accordion, string id, string title, List<HealthcheckAccountDetailData> list, string tooltip = null)
        {
            if (list == null)
            {
                return;
            }
            bool eventDate = false;
            foreach (var u in list)
            {
                if (u.Event != DateTime.MinValue)
                {
                    eventDate = true;
                    break;
                }
            }
            GenerateAccordionDetailForDetail(id, accordion, title, list.Count, () =>
                {
                    AddBeginTable("Account list");
                    AddHeaderText("Name");
                    AddHeaderText("Creation");
                    AddHeaderText("Last logon");
                    AddHeaderText("Pwd Last Set");
                    if (eventDate)
                    {
                        AddHeaderText("Event date");
                    }
                    AddHeaderText("Distinguished name");
                    AddBeginTableData();

                    int number = 0;
                    list.Sort((HealthcheckAccountDetailData a, HealthcheckAccountDetailData b)
                        =>
                        {
                            return String.Compare(a.Name, b.Name);
                        }
                        );
                    foreach (HealthcheckAccountDetailData detail in list)
                    {
                        AddBeginRow();
                        AddCellText(detail.Name);
                        AddCellText((detail.CreationDate > DateTime.MinValue ? detail.CreationDate.ToString("u") : "Access Denied"));
                        AddCellText((detail.LastLogonDate > DateTime.MinValue ? detail.LastLogonDate.ToString("u") : "Never"));
                        AddCellText((detail.PwdLastSet > DateTime.MinValue ? detail.PwdLastSet.ToString("u") : "Never"));
                        if (eventDate)
                        {
                            if (detail.Event == DateTime.MinValue)
                            {
                                AddCellText("Unknown");
                            }
                            else
                            {
                                AddCellText(detail.Event.ToString("u"));
                            }
                        }
                        AddCellText(detail.DistinguishedName);
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
                            Add(eventDate ? 5 : 4);
                            Add("' class='text'>");
                            AddEncoded(string.Format(MaxNumberUsersInHtmlReportMessage, MaxNumberUsersInHtmlReport));
                            Add("</td>");
                        }
                    });
                }, tooltip: tooltip);
        }

        private void GenerateDomainSIDHistoryList(HealthcheckAccountData data)
        {
            if (data.ListDomainSidHistory == null || data.ListDomainSidHistory.Count == 0)
                return;

            GenerateSubSection("SID History", "sidhistory");
            AddBeginTable("SID History list");
            AddHeaderText("SID History from domain");
            AddHeaderText("First date seen", "This is the oldest creation date of an object having SIDHistory related to this domain");
            AddHeaderText("Last date seen", "This is the youngest creation date of an object having SIDHistory related to this domain");
            AddHeaderText("Count");
            if (Report.version >= new Version(2, 9))
            {
                AddHeaderText("Dangerous SID Found");
            }
            AddBeginTableData();

            data.ListDomainSidHistory.Sort(
                (HealthcheckSIDHistoryData x, HealthcheckSIDHistoryData y) =>
                {
                    return String.Compare(x.FriendlyName, y.FriendlyName);
                }
                );
            foreach (HealthcheckSIDHistoryData domainSidHistory in data.ListDomainSidHistory)
            {
                AddBeginRow();
                AddCellText(domainSidHistory.FriendlyName);
                AddCellDate(domainSidHistory.FirstDate);
                AddCellDate(domainSidHistory.LastDate);
                AddCellNum(domainSidHistory.Count);
                if (Report.version >= new Version(2, 9))
                {
                    AddCellText(domainSidHistory.DangerousSID.ToString());
                }
                AddEndRow();
            }
            AddEndTable();
        }

        #endregion user info
        #region computer info
        protected void GenerateComputerInformation()
        {
            GenerateSubSection("Account analysis", "computeraccountanalysis");
            AddParagraph("This section gives information about the computer accounts stored in the Active Directory");
            AddBeginTable("Computer information list", true);
            AddHeaderText("Nb Computer Accounts");
            AddAccountCheckHeader(true);
            AddBeginTableData();

            AddBeginRow();
            AddCellNum(Report.ComputerAccountData.Number);
            AddCellNum(Report.ComputerAccountData.NumberEnabled);
            AddCellNum(Report.ComputerAccountData.NumberDisabled);
            AddCellNum(Report.ComputerAccountData.NumberActive);
            SectionList("computersaccordion", "sectioninactivecomputer", Report.ComputerAccountData.NumberInactive, Report.ComputerAccountData.ListInactive);
            SectionList("computersaccordion", "sectionsidhistorycomputer", Report.ComputerAccountData.NumberSidHistory, Report.ComputerAccountData.ListSidHistory);
            SectionList("computersaccordion", "sectionbadprimarygroupcomputer", Report.ComputerAccountData.NumberBadPrimaryGroup, Report.ComputerAccountData.ListBadPrimaryGroup);
            SectionList("computersaccordion", "sectiontrusteddelegationcomputer", Report.ComputerAccountData.NumberTrustedToAuthenticateForDelegation, Report.ComputerAccountData.ListTrustedToAuthenticateForDelegation);
            SectionList("computersaccordion", "sectionreversiblencomputer", Report.ComputerAccountData.NumberReversibleEncryption, Report.ComputerAccountData.ListReversibleEncryption);
            AddEndRow();
            AddEndTable();

            GenerateListAccount(Report.ComputerAccountData, "computer", "computersaccordion");
            GenerateOperatingSystemList();
            GenerateDomainSIDHistoryList(Report.ComputerAccountData);
            GenerateDCInformation();


            GenerateSubSection("LAPS Analysis", "lapsanalysis");
            if (_license.IsBasic())
            {
                AddParagraph("This feature is reserved for customers who have <a href='https://www.pingcastle.com/services/'>purchased a license</a>");
            }
            else
            {
                if ((Report.LapsDistribution != null && Report.LapsDistribution.Count > 0) || (Report.LapsNewDistribution != null && Report.LapsNewDistribution.Count > 0))
                {
                    AddParagraph("Here is the distribution of the LAPS password fresshness (legacy vs the new Microsoft extension).");
                    if (Report.NewLAPSInstalled == DateTime.MinValue)
                    {
                        // if chart if for legacy values
                        AddDistributionChart(Report.LapsDistribution.Select(x => new DistributionItem { HigherBound = x.HigherBound, Value = x.Value }), "generallapsdistribution");
                    }
                    else
                    {
                        AddDistributionSeriesChart(new Dictionary<string, IEnumerable<DistributionItem>>
                        {
                            {"Legacy LAPS", Report.LapsDistribution == null ? null : Report.LapsDistribution.Select(x => new DistributionItem { HigherBound = x.HigherBound, Value = x.Value })},
                            {"New LAPS", Report.LapsNewDistribution == null ? null : Report.LapsNewDistribution.Select(x => new DistributionItem { HigherBound = x.HigherBound, Value = x.Value })},
                        }, "generallapsdistribution");
                    }
                    if (Report.ComputerAccountData != null && Report.OperatingSystemVersion != null)
                    {
                        AddParagraph("Here is the application of LAPS");
                        var note = "Note: LAPS cannot be installed on Domain controllers. As a consequence LAPS cannot be deployed on 100% of the servers.";
                        if (Report.DomainControllers != null)
                        {
                            note += " There is currently " + Report.DomainControllers.Count + " domain controllers or AzureAD gateway listed in this report.";
                        }
                        AddParagraph(note);

                        Add("<div class='row'>");


                        int total = 0; 
                        var laps = new List<int>();
                        var tooltip = new List<string>();
                        int totalServer = 0; 
                        var lapsServer = new List<int>();
                        var tooltipServer = new List<string>();

                        // ToDo: there is no link between laps int list and its tooltip, they only connection is the shared index.
                        // It's probably worth changing it to a connected structure that would contain Legacy LAPS number, Windows LAPS number and the tooltip (or data for its generation)
                        // Like at least Class LAPSData (int LegacyLAPS, int WindowsLAPS, string Tooltip)
                        foreach (var os in Report.OperatingSystemVersion)
                        {

                            if (!os.IsServer)
                            {
                                total += os.data.NumberEnabled;
                                if (os.data.NumberLAPS != 0 || os.data.NumberLAPSNew != 0)
                                {
                                    laps.Add(os.data.NumberLAPS + os.data.NumberLAPSNew);
                                    tooltip.Add(GetOSVersionString(os) + " [" + os.data.NumberEnabled + " - " + Math.Round((decimal)(os.data.NumberLAPS + os.data.NumberLAPSNew) * 100 / os.data.NumberEnabled) + "%]");
                                }
                            }
                            else
                            {
                                totalServer += os.data.NumberEnabled;
                                if (os.data.NumberLAPS != 0 || os.data.NumberLAPSNew != 0)
                                {
                                    lapsServer.Add(os.data.NumberLAPS + os.data.NumberLAPSNew);
                                    tooltipServer.Add(GetOSVersionString(os) + " [" + os.data.NumberEnabled + " - " + Math.Round((decimal)(os.data.NumberLAPS + os.data.NumberLAPSNew) * 100 / os.data.NumberEnabled) + "%]");
                                }
                            }
                        }

                        Add("<div class='col-lg-4'>");
                        Add(@"<div class=""card"">
  <div class=""card-body"">
    <h5 class=""card-title"">Enabled computers with LAPS (");
                        Add((laps.Sum()+ lapsServer.Sum()).ToString("#,##0"));
                        Add(@") over all enabled computers (");
                        Add((total + totalServer).ToString("#,##0"));
                        Add(@")</h5>
    ");
                        AddPie(50, Report.ComputerAccountData.NumberEnabled, Report.ComputerAccountData.NumberLAPS, Report.ComputerAccountData.NumberLAPSNew);
                        Add(@"
  </div>
</div>");
                        Add("</div>");

                        Add("<div class='col-lg-4'>");
                        Add(@"<div class=""card"">
  <div class=""card-body"">
    <h5 class=""card-title"">Enabled workstations with LAPS (");
                        Add(laps.Sum().ToString("#,##0"));
                        Add(@") over all enabled workstations (");
                        Add(total.ToString("#,##0"));
                        Add(@")</h5>
    ");
                        AddPie(50, total, laps, tooltip);
                        Add(@"
  </div>
</div>");
                        Add("</div>");

                        Add("<div class='col-lg-4'>");
                        Add(@"<div class=""card"">
  <div class=""card-body"">
    <h5 class=""card-title"">Enabled servers with LAPS (");
                        Add(lapsServer.Sum().ToString("#,##0"));
                        Add(@") over all enabled servers (");
                        Add(totalServer.ToString("#,##0"));
                        Add(@")</h5>
    ");
                        AddPie(50, totalServer, lapsServer, tooltipServer);
                        Add(@"
  </div>
</div>");
                        Add("</div>");

                        Add("</div>");

                        AddBeginTable("lapsos");
                        AddHeaderText("Operating System");
                        AddHeaderText("Number of Enabled");
                        AddHeaderText("Number of Legacy LAPS");
                        AddHeaderText("Number of Windows LAPS");
                        AddHeaderText("Number of LAPS Total");
                        AddHeaderText("Ratio (%)");
                        AddBeginTableData();
                        foreach (var os in Report.OperatingSystemVersion)
                        {
                            AddBeginRow();
                            AddCellText(GetOSVersionString(os));
                            AddCellNum(os.data.NumberEnabled);
                            AddCellNum(os.data.NumberLAPS);
                            AddCellNum(os.data.NumberLAPSNew);
                            AddCellNum(os.data.NumberLAPS + os.data.NumberLAPSNew);
                            if (os.data.NumberEnabled > 0)
                            {
                                AddCellNum((int)Math.Round((decimal)(os.data.NumberLAPS + os.data.NumberLAPSNew) * 100 / os.data.NumberEnabled));
                            }
                            else
                            {
                                AddCellText();
                            }
                            AddEndRow();
                        }
                        AddEndTable();

                    }
                }
                else
                {
                    AddParagraph("No data is available in the report or no computers are enforcing LAPS.");
                }
            }
        }

        private void GenerateOperatingSystemList()
        {
            GenerateSubSection("Operating Systems", "operatingsystems");
            AddParagraph("If you need to find the computers running a specific OS, we advise to use PingCastle.exe and the export / computers feature available from the main menu. " +
                        "Indeed the computer details are not included in the report for performance issues. Doing this will impact significantly the report size and the time to load the report.");
            bool oldOS = Report.version <= new Version(2, 5, 0, 0);
            if (oldOS)
            {
                AddBeginTable("Operating System list");
                AddHeaderText("Operating System");
                AddHeaderText("Count");
                AddBeginTableData();
                Report.OperatingSystem.Sort(
                    (HealthcheckOSData x, HealthcheckOSData y) =>
                    {
                        return OrderOS(x.OperatingSystem, y.OperatingSystem);
                    }
                    );
                {
                    foreach (HealthcheckOSData os in Report.OperatingSystem)
                    {
                        AddBeginRow();
                        AddCellText(os.OperatingSystem);
                        AddCellNum(os.NumberOfOccurence);
                        AddEndRow();
                    }
                }
                AddEndTable();
            }
            else if (Report.OperatingSystemVersion == null || Report.OperatingSystemVersion.Count == 0)
            {
                AddBeginTable("Operating System list");
                AddHeaderText("Operating System");
                AddHeaderText("Nb OS");
                AddAccountCheckHeader(true);
                AddBeginTableData();

                Report.OperatingSystem.Sort(
                    (HealthcheckOSData x, HealthcheckOSData y) =>
                    {
                        return OrderOS(x.OperatingSystem, y.OperatingSystem);
                    }
                    );
                {
                    foreach (HealthcheckOSData os in Report.OperatingSystem)
                    {
                        AddBeginRow();
                        AddCellText(os.OperatingSystem);
                        AddCellNum(os.data.Number);
                        AddCellNum(os.data.NumberEnabled);
                        AddCellNum(os.data.NumberDisabled);
                        AddCellNum(os.data.NumberActive);
                        AddCellNum(os.data.NumberInactive);
                        AddCellNum(os.data.NumberSidHistory);
                        AddCellNum(os.data.NumberBadPrimaryGroup);
                        AddCellNum(os.data.NumberTrustedToAuthenticateForDelegation);
                        AddCellNum(os.data.NumberReversibleEncryption);
                        AddEndRow();
                    }
                }
                AddEndTable();
            }
            else
            {
                AddBeginTable("Operating System list");
                AddHeaderText("Operating System");
                AddHeaderText("Nb OS");
                AddAccountCheckHeader(true);
                AddBeginTableData();

                foreach (HealthcheckOSData os in Report.OperatingSystem)
                {
                    if (os.OperatingSystem.Contains("Windows"))
                        continue;
                    AddBeginRow();
                    AddCellText(os.OperatingSystem);
                    AddCellNum(os.data.Number);
                    AddCellNum(os.data.NumberEnabled);
                    AddCellNum(os.data.NumberDisabled);
                    AddCellNum(os.data.NumberActive);
                    AddCellNum(os.data.NumberInactive);
                    AddCellNum(os.data.NumberSidHistory);
                    AddCellNum(os.data.NumberBadPrimaryGroup);
                    AddCellNum(os.data.NumberTrustedToAuthenticateForDelegation);
                    AddCellNum(os.data.NumberReversibleEncryption);
                    AddEndRow();
                }
                foreach (HealthcheckOSVersionData os in Report.OperatingSystemVersion)
                {
                    AddBeginRow();
                    AddCellText(GetOSVersionString(os));
                    AddCellNum(os.data.Number);
                    AddCellNum(os.data.NumberEnabled);
                    AddCellNum(os.data.NumberDisabled);
                    AddCellNum(os.data.NumberActive);
                    AddCellNum(os.data.NumberInactive);
                    AddCellNum(os.data.NumberSidHistory);
                    AddCellNum(os.data.NumberBadPrimaryGroup);
                    AddCellNum(os.data.NumberTrustedToAuthenticateForDelegation);
                    AddCellNum(os.data.NumberReversibleEncryption);
                    AddEndRow();
                }
                AddEndTable();
            }
        }

        private void GenerateDCInformation()
        {
            if (Report.DomainControllers == null || Report.DomainControllers.Count == 0)
                return;

            GenerateSubSection("Domain controllers", "domaincontrollersection");
            AddParagraph("Here is a specific zoom related to the Active Directory servers: the domain controllers.");
            GenerateAccordion("domaincontrollers", ()
                =>
                {
                    GenerateAccordionDetailForDetail("domaincontrollersdetail", "domaincontrollers", "Domain controllers", Report.DomainControllers.Count,
                        () =>
                        {
                            AddBeginTable("Domain Controllers list");
                            AddHeaderText("Domain controller");
                            AddHeaderText("Operating System");
                            AddHeaderText("Creation Date", "Indicates the creation date of the underlying computer object.");
                            AddHeaderText("Startup Time");
                            AddHeaderText("Uptime");
                            AddHeaderText("Owner", "This is the owner of the underlying domain controller object stored in the active directory partition. The nTSecurityDescriptor attribute stores its value.");
                            AddHeaderText("Null sessions", "Indicates if an anonymous user can extract information from the domain controller");
                            AddHeaderText("SMB v1", "Indicates if the domain controller supports the unsafe SMB v1 network protocol.");
                            if (Report.version >= new Version(2, 5, 3))
                            {
                                AddHeaderText("Remote spooler", "Indicates if the spooler service is remotely accessible.");
                            }
                            if (Report.version >= new Version(2, 7))
                            {
                                AddHeaderText("FSMO role", "Flexible Single Master Operation. Indicates the server responsible for each role.");
                            }
                            if (Report.version >= new Version(2, 11))
                            {
                                AddHeaderText("WebDAV", "Detect if the WebClient service is running, which provide the ability to call http server from native command line.");
                            }
                            AddBeginTableData();

                            int count = 0;
                            foreach (var dc in Report.DomainControllers)
                            {
                                count++;
                                AddBeginRow();
                                AddCellText(dc.DCName);
                                AddCellText(dc.OperatingSystem);
                                AddCellText((dc.CreationDate == DateTime.MinValue ? "Unknown" : dc.CreationDate.ToString("u")));
                                AddCellText((dc.StartupTime == DateTime.MinValue ? (dc.LastComputerLogonDate.AddDays(60) < DateTime.Now ? "Inactive?" : "Unknown") : (dc.StartupTime.AddMonths(6) < DateTime.Now ? /*"<span class='unticked'>" + */dc.StartupTime.ToString("u")/* + "</span>"*/ : dc.StartupTime.ToString("u"))));
                                AddCellText((dc.StartupTime == DateTime.MinValue ? "" : (DateTime.Now.Subtract(dc.StartupTime)).Days.ToString("D3") + " days"));
                                AddCellText((String.IsNullOrEmpty(dc.OwnerName) ? dc.OwnerSID : dc.OwnerName));
                                AddCellText((dc.HasNullSession ? "YES" : "NO"), true, !dc.HasNullSession);
                                AddCellText((dc.SupportSMB1 ? "YES" : "NO"), true, !dc.SupportSMB1);

                                if (Report.version >= new Version(2, 5, 3))
                                {
                                    AddCellText((dc.RemoteSpoolerDetected ? "YES" : "NO"), true, !dc.RemoteSpoolerDetected);
                                }
                                if (Report.version >= new Version(2, 7))
                                {
                                    Add(@"<Td>");
                                    if (dc.FSMO != null)
                                    {
                                        Add(string.Join(",<br>", dc.FSMO.ConvertAll(x => ReportHelper.Encode(x)).ToArray()));
                                    }
                                    Add("</Td>");
                                }
                                if (Report.version >= new Version(2, 11))
                                {
                                    AddCellText((dc.WebClientEnabled ? "YES" : "NO"), true, !dc.WebClientEnabled);
                                }
                                AddEndRow();
                            }
                            AddEndTable();
                        }
                    );
                }
            );

        }


        #endregion computer info

        #region admin groups
        protected void GenerateAdminGroupsInformation()
        {
            if (Report.PrivilegedGroups != null)
            {
                GenerateSubSection("Groups", "admingroups");
                AddParagraph("This section is focused on the groups which are critical for admin activities. If the report has been saved which the full details, each group can be zoomed with its members. If it is not the case, for privacy reasons, only general statistics are available.");
                AddBeginTable("Admin groups list");
                AddHeaderText("Group Name");
                AddHeaderText("Nb Admins", "This is the number of user accounts member of this group");
                AddHeaderText("Nb Enabled", "This is the number of user accounts not marked as disabled");
                AddHeaderText("Nb Disabled", "This is the number of user accounts marked as disabled");
                AddHeaderText("Nb Inactive", "This is the number of enabled user accounts without login activities far at least 6 months");
                AddHeaderText("Nb PWd never expire", "This is the number of enabled user accounts having a password marked as never expire");
                if (Report.version >= new Version(2, 5, 2))
                {
                    AddHeaderText("Nb Smart Card required", "This is the number of enabled user accounts required to have a smart card");
                }
                if (Report.version >= new Version(2, 5, 3))
                {
                    AddHeaderText("Nb Service accounts", "This is the number of enabled user accounts authorized to be a service. This is defined by setting the attribute servicePrincipalName.");
                }
                AddHeaderText("Nb can be delegated", "This is the number of enabled user accounts which doesn't have the flag 'this account is sensitive and cannot be delegated'. This is an effective mitigation against unconstrained delegation attacks.");
                AddHeaderText("Nb external users", "This is the number of item identified as coming from a foreign domain");
                if (Report.version >= new Version(2, 9))
                {
                    AddHeaderText("Nb protected users", "This is the number of users in the Protected Users group");
                }
                AddBeginTableData();

                Report.PrivilegedGroups.Sort((HealthCheckGroupData a, HealthCheckGroupData b)
                    =>
                    {
                        return String.Compare(a.GroupName, b.GroupName);
                    }
                );
                foreach (HealthCheckGroupData group in Report.PrivilegedGroups)
                {
                    AddBeginRow();
                    if (group.Members != null && group.Members.Count > 0)
                    {
                        Add(@"<td class='text'><a data-bs-toggle=""modal"" href=""#");
                        Add(GenerateModalAdminGroupIdFromGroupName(group.GroupName));
                        Add(@""">");
                        AddEncoded(group.GroupName);
                        Add("</a></td>");
                    }
                    else
                    {
                        AddCellText(group.GroupName);
                    }
                    AddCellNum(group.NumberOfMember);
                    AddCellNum(group.NumberOfMemberEnabled);
                    AddCellNum(group.NumberOfMemberDisabled);
                    AddCellNum(group.NumberOfMemberInactive);
                    AddCellNum(group.NumberOfMemberPwdNeverExpires);
                    if (Report.version >= new Version(2, 5, 2))
                    {
                        AddCellNum(group.NumberOfSmartCardRequired);
                    }
                    if (Report.version >= new Version(2, 5, 3))
                    {
                        AddCellNum(group.NumberOfServiceAccount);
                    }
                    AddCellNum(group.NumberOfMemberCanBeDelegated);
                    AddCellNum(group.NumberOfExternalMember);
                    if (Report.version >= new Version(2, 9))
                    {
                        AddCellNum(group.NumberOfMemberInProtectedUsers);
                    }
                    AddEndRow();
                }
                AddEndTable();
                foreach (HealthCheckGroupData group in Report.PrivilegedGroups)
                {
                    if (group.Members != null && group.Members.Count > 0)
                    {
                        AddBeginModal(GenerateModalAdminGroupIdFromGroupName(group.GroupName), group.GroupName, ShowModalType.XL);
                        GenerateAdminGroupsDetail(group.Members);
                        AddEndModal();
                    }
                }
            }

            if (Report.AllPrivilegedMembers != null && Report.AllPrivilegedMembers.Count > 0)
            {
                Add(@"
		<div class=""row"">
			<div class=""col-md-12"">
");
                GenerateAccordion("admingroupsaccordeon",
                    () =>
                    {
                        GenerateAccordionDetailForDetail("allprivileged", "admingroupsaccordeon", "All users in Admins groups", Report.AllPrivilegedMembers.Count, () => GenerateAdminGroupsDetail(Report.AllPrivilegedMembers));
                    });
                Add("</div></div>");
            }
            if (Report.ProtectedUsersNotPrivileged != null && Report.ProtectedUsersNotPrivileged.Members != null && Report.ProtectedUsersNotPrivileged.Members.Count > 0)
            {
                Add(@"
		<div class=""row"">
			<div class=""col-md-12"">
");
                GenerateAccordion("protectedusersaccordeon",
                    () =>
                    {
                        GenerateAccordionDetailForDetail("protectedusers", "protectedusersaccordeon", "Protected Users and not Admins", Report.ProtectedUsersNotPrivileged.Members.Count, () => GenerateAdminGroupsDetail(Report.ProtectedUsersNotPrivileged.Members));
                    });
                Add("</div></div>");
            }
            GenerateSubSection("Last Logon Distribution", "adminlastlogondistribution");
            if (_license.IsBasic())
            {
                AddParagraph("This feature is reserved for customers who have <a href='https://www.pingcastle.com/services/'>purchased a license</a>");
            }
            else
            {
                var lastLogon = new List<DistributionItem>();
                var pwdLastSet = new List<DistributionItem>();

                ComputePrivilegedDistribution(lastLogon, pwdLastSet);

                if (lastLogon.Count == 0)
                    lastLogon = Report.PrivilegedDistributionLastLogon.Select(x => new DistributionItem { HigherBound = x.HigherBound, Value = x.Value }).ToList();
                if (lastLogon != null && lastLogon.Count > 0)
                {
                    AddParagraph("Here is the distribution of the last logon of privileged users. Only enabled accounts are analyzed.");
                    AddDistributionChart(lastLogon, "logonadmin");
                }

                GenerateSubSection("Password Age Distribution", "adminpwdagedistribution");
                if (pwdLastSet.Count == 0)
                    pwdLastSet = Report.PrivilegedDistributionPwdLastSet.Select(x => new DistributionItem { HigherBound = x.HigherBound, Value = x.Value }).ToList();
                if (pwdLastSet != null && pwdLastSet.Count > 0)
                {
                    AddParagraph("Here is the distribution of the password age for privileged users. Only enabled accounts are analyzed.");
                    AddDistributionChart(pwdLastSet, "pwdlastsetadmin");
                }
            }
            if (Report.Delegations != null && Report.Delegations.Count > 0)
            {
                Add(@"
		<div class=""row"">
			<div class=""col-md-12"">
");
                GenerateSubSection("Delegations", "admindelegation");
                AddParagraph("Each specific rights defined for Organizational Unit (OU) are listed below.");
                GenerateAccordion("delegationaccordeon",
                    () =>
                    {
                        GenerateAccordionDetailForDetail("alldelegation", "delegationaccordeon", "All delegations", Report.Delegations.Count, () => GenerateDelegationDetail(Report.Delegations));
                    });
                Add("</div></div>");

                if (Report.UnprotectedOU != null && Report.UnprotectedOU.Count > 0)
                {
                    Add(@"
		<div class=""row"">
			<div class=""col-lg-12"">");
                    AddParagraph("The OU that are listed as not protected are:");
                    GenerateAccordion("unprotectedOUaccordeon",
                        () =>
                        {
                            GenerateAccordionDetailForDetail("unprotectedOU", "unprotectedOUaccordeon", "Unprotected OU", Report.UnprotectedOU.Count, () => GenerateUnprotectedOUDetail(Report.UnprotectedOU));
                        });
                    Add(@"
			</div>
		</div>
");
                }

                List<HealthcheckDelegationData> dcsync = new List<HealthcheckDelegationData>();
                foreach (var d in Report.Delegations)
                    if (d.Right.Contains(RelationType.EXT_RIGHT_REPLICATION_GET_CHANGES_ALL.ToString()))
                        dcsync.Add(d);
                AddParagraph("In particular for AD database access (DCSync, AADConnect, ...).");
                GenerateAccordion("delegationaccordeondcsync",
                    () =>
                    {
                        GenerateAccordionDetailForDetail("dcsyncdelegation", "delegationaccordeondcsync", "AD Database Access", dcsync.Count,
                            () => GenerateDelegationDetail(dcsync));
                    });
            }
        }

        private void ComputePrivilegedDistribution(List<DistributionItem> lastLogon, List<DistributionItem> pwdLastSet)
        {
            if (Report.AllPrivilegedMembers != null && Report.AllPrivilegedMembers.Count > 0)
            {
                var pwdDistribution = new Dictionary<int, DistributionItem>();
                var logonDistribution = new Dictionary<int, DistributionItem>();
                foreach (var user in Report.AllPrivilegedMembers)
                {
                    if (user.IsEnabled)
                    {
                        int i;
                        if (user.LastLogonTimestamp != DateTime.MinValue)
                        {
                            i = HealthcheckAnalyzer.ConvertDateToKey(user.LastLogonTimestamp);
                        }
                        else
                        {
                            i = 10000;
                        }

                        if (logonDistribution.ContainsKey(i))
                        {
                            logonDistribution[i].Value++;
                            logonDistribution[i].toolTip += "\r\n" + user.Name;
                        }
                        else
                        {
                            logonDistribution[i] = new DistributionItem { HigherBound = i, Value = 1, toolTip = user.Name };
                        }

                        if (user.PwdLastSet != DateTime.MinValue)
                        {
                            i = HealthcheckAnalyzer.ConvertDateToKey(user.PwdLastSet);
                        }
                        else
                        {
                            i = HealthcheckAnalyzer.ConvertDateToKey(user.Created);
                        }
                        if (pwdDistribution.ContainsKey(i))
                        {
                            pwdDistribution[i].Value++;
                            pwdDistribution[i].toolTip += "\r\n" + user.Name;
                        }
                        else
                        {
                            pwdDistribution[i] = new DistributionItem { HigherBound = i, Value = 1, toolTip = user.Name };
                        }
                    }
                }
            }
        }

        private string GenerateModalAdminGroupIdFromGroupName(string groupname)
        {
            return "modal" + groupname.Replace(" ", "-").Replace("<", "");
        }

        private void GenerateDelegationDetail(List<HealthcheckDelegationData> delegations)
        {
            AddBeginTable("Delegations list");
            AddHeaderText("DistinguishedName");
            AddHeaderText("Account");
            AddHeaderText("Right");
            AddBeginTableData();

            delegations.Sort(OrderDelegationData);

            foreach (HealthcheckDelegationData delegation in delegations)
            {
                int dcPathPos = delegation.DistinguishedName.IndexOf(",DC=");
                string path = delegation.DistinguishedName;
                if (dcPathPos > 0)
                    path = delegation.DistinguishedName.Substring(0, dcPathPos);
                AddBeginRow();
                AddCellText(path);
                AddCellText(delegation.Account);
                AddCellText(delegation.Right);
                AddEndRow();
            }
            AddEndTable();
        }

        private void GenerateAdminGroupsDetail(List<HealthCheckGroupMemberData> members)
        {
            if (members != null)
            {
                AddBeginTable("Admin groups detail");
                AddHeaderText("SamAccountName", "Indicates login name of the user account.");
                AddHeaderText("Enabled", "Indicates if the account is not marked as disabled.");
                AddHeaderText("Active", "Indicates if the user is not set as disabled and at least one login occured during the last 6 months.");
                AddHeaderText("Pwd never Expired", "Indicates for enabled accounts if the password is set to never expires.");
                AddHeaderText("Locked", "Indicates for enabled accounts if the account is locked");
                if (Report.version >= new Version(2, 5, 2))
                {
                    AddHeaderText("Smart Card required", "Indicates for enabled accounts if a smart card is required to login");
                }
                if (Report.version >= new Version(2, 5, 3))
                {
                    AddHeaderText("Service account", "Indicates for enabled accounts if it has been marked as service. This is done by setting the servicePrincipalName attribute.");
                }
                AddHeaderText("Flag Cannot be delegated present", "Indicates for enabled accounts if the protection 'this is account is sensitive and cannot be delegated' is in place.");
                if (Report.version >= new Version(2, 8, 0))
                {
                    AddHeaderText("Creation date", "Indicates when the account has been created.");
                }
                AddHeaderText("Last login", "Indicates the last login date. Note: this value has a 14 days error margin.");
                AddHeaderText("Password last set", "Indicates when the password has been changed for the last time");
                if (Report.version >= new Version(2, 9, 0))
                {
                    AddHeaderText("In Protected Users", "Indicates if the account is a member of the special group Protected Users.");
                }
                AddHeaderText("Distinguished name", "Indicates the location of the object in the AD tree.");
                AddBeginTableData();
                members.Sort((HealthCheckGroupMemberData a, HealthCheckGroupMemberData b)
                    =>
                        {
                            return String.Compare(a.Name, b.Name);
                        }
                );
                foreach (HealthCheckGroupMemberData member in members)
                {
                    if (member.IsExternal)
                    {
                        AddBeginRow();
                        AddCellText(member.Name);
                        AddCellText("External");
                        AddCellText("External");
                        AddCellText("External");
                        AddCellText("External");
                        AddCellText("External");
                        if (Report.version >= new Version(2, 5, 2))
                        {
                            AddCellText("External");
                        }
                        if (Report.version >= new Version(2, 5, 3))
                        {
                            AddCellText("External");
                        }
                        if (Report.version >= new Version(2, 8, 0))
                        {
                            AddCellText("External");
                        }
                        AddCellText("External");
                        AddCellText("External");
                        if (Report.version >= new Version(2, 9, 0))
                        {
                            AddCellText("External");
                        }
                        AddCellText(member.DistinguishedName);
                        AddEndRow();
                    }
                    else
                    {
                        AddBeginRow();
                        AddCellText(member.Name);
                        AddCellText((member.IsEnabled ? "YES" : "NO"), true, member.IsEnabled);
                        AddCellText((member.IsActive ? "YES" : "NO"), true, member.IsActive);
                        AddCellText((member.DoesPwdNeverExpires ? "YES" : "NO"), true, !member.DoesPwdNeverExpires);
                        AddCellText((member.IsLocked ? "YES" : "NO"), true, !member.IsLocked);
                        if (Report.version >= new Version(2, 5, 2))
                        {
                            AddCellText((member.SmartCardRequired ? "YES" : "NO"), true, member.SmartCardRequired);
                        }
                        if (Report.version >= new Version(2, 5, 3))
                        {
                            AddCellText((member.IsService ? "YES" : "NO"), true, !member.IsService);
                        }
                        AddCellText((!member.CanBeDelegated ? "YES" : "NO"), true, !member.CanBeDelegated);
                        if (Report.version >= new Version(2, 8, 0))
                        {
                            AddCellDate(member.Created);
                        }
                        AddCellDate(member.LastLogonTimestamp);
                        AddCellDate(member.PwdLastSet);
                        if (Report.version >= new Version(2, 9, 0))
                        {
                            AddCellText((member.IsInProtectedUser ? "YES" : "NO"), true, member.IsInProtectedUser);
                        }
                        AddCellText(member.DistinguishedName);
                        AddEndRow();
                    }
                }
                AddEndTable();
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

        #region compromission graph analysis
        protected void GenerateCompromissionGraphInformation()
        {
            if (Report.ControlPaths == null)
                return;
            AddAnchor("controlpath");
            GenerateCompromissionGraphDependanciesInformation();
            GenerateCompromissionGraphIndirectLinksInformation();
            GenerateCompromissionGraphDetailedAnalysis();
            GenerateCompromissionGraphJasonOutput();
        }

        protected void GenerateCompromissionGraphDependanciesInformation()
        {
            AddParagraph("This section focuses on permissions issues that can be exploited to take control of the domain.<br>This is an advanced section that should be examined after having looked at the <a href='#admingroups'>Admin Groups</a> section.");
            GenerateSubSection("Foreign domain involved", "cgtrust");
            AddParagraph("This analysis focuses on accounts found in control path and located in other domains.");
            if (Report.ControlPaths.Dependancies == null || Report.ControlPaths.Dependancies.Count == 0)
            {
                AddParagraph("No operative link with other domains has been found.");
                return;
            }

            AddParagraph("The following table lists all the foreign domains whose compromise can impact this domain. The impact is listed by typology of objects.");
            AddBeginTable("Compromise graph dependancies list");
            AddHeaderText("FQDN", rowspan: 2);
            AddHeaderText("NetBIOS", rowspan: 2);
            AddHeaderText("SID", rowspan: 2);

            int numTypology = 0;
            foreach (var typology in (CompromiseGraphDataTypology[])Enum.GetValues(typeof(CompromiseGraphDataTypology)))
            {
                AddHeaderText(ReportHelper.GetEnumDescription(typology), colspan: 3);
                numTypology++;
            }
            AddEndRow();
            AddBeginRow();
            for (int i = 0; i < numTypology; i++)
            {
                AddHeaderText("Group", "Number of group impacted by this domain");
                AddHeaderText("Resolved", "Number of unique SID (account, group, computer, ...) resolved");
                AddHeaderText("Unresolved", "Number of unique SID (account, group, computer, ...) NOT resolved meaning that the underlying object may have been removed");
            }
            AddBeginTableData();
            foreach (var header in Report.ControlPaths.Dependancies)
            {
                AddBeginRow();
                Add("<td class='text'>");
                if (GetUrlCallbackDomain == null)
                {
                    AddEncoded(header.FQDN);
                }
                else
                {
                    Add(GetUrlCallbackDomain(header.Domain, !string.IsNullOrEmpty(header.FQDN) ? header.FQDN : header.Netbios, null));
                }
                Add("</td>");
                AddCellText(header.Netbios);
                AddCellText(header.Sid);
                foreach (var typology in (CompromiseGraphDataTypology[])Enum.GetValues(typeof(CompromiseGraphDataTypology)))
                {
                    bool found = false;
                    foreach (var item in header.Details)
                    {
                        if (item.Typology != typology)
                            continue;
                        found = true;
                        AddCellNum(item.NumberOfGroupImpacted);
                        AddCellNum(item.NumberOfResolvedItems);
                        AddCellNum(item.NumberOfUnresolvedItems);
                        break;
                    }
                    if (!found)
                    {
                        AddCellNum(0, true);
                        AddCellNum(0, true);
                        AddCellNum(0, true);
                    }
                }
                AddEndRow();
            }
            AddEndTable();
        }

        protected void GenerateCompromissionGraphIndirectLinksInformation()
        {
            GenerateSubSection("Indirect links", "cgindirectlinks");
            AddParagraph("This part tries to summarize in a single table if major issues have been found.<br>Focus on finding critical objects such as the Everyone group then try to decrease the number of objects having indirect access.<br>The detail is displayed below.");
            if (Report.ControlPaths.AnomalyAnalysis == null || Report.ControlPaths.AnomalyAnalysis.Count == 0)
            {
                AddParagraph("No data has been found.");
                return;
            }
            AddBeginTable("Compromise Grapth Indirect links list");
            AddHeaderText("Priority to remediate", "Indicates a set of objects considered as a priority when establishing a remediation plan.");
            AddHeaderText("Critical Object Found", "Indicates if critical objects such as everyone, authenticated users or domain users can take control, directly or not, of one of the objects.");
            AddHeaderText("Number of objects with Indirect", "Indicates the count of objects per category having at least one indirect user detected.");
            AddHeaderText("Max number of indirect numbers", "Indicates the maximum on all objects of the number of users having indirect access to the object.");
            AddHeaderText("Max ratio", "Indicates in percentage the value of (number of indirect users / number of direct users) if at least one direct users exists. Else the value is zero.");
            AddBeginTableData();
            foreach (var objectRisk in (CompromiseGraphDataObjectRisk[])Enum.GetValues(typeof(CompromiseGraphDataObjectRisk)))
            {
                AddBeginRow();
                AddHeaderText(ReportHelper.GetEnumDescription(objectRisk));
                bool found = false;
                foreach (var analysis in Report.ControlPaths.AnomalyAnalysis)
                {
                    if (analysis.ObjectRisk != objectRisk)
                        continue;
                    found = true;
                    AddCellText(analysis.CriticalObjectFound ? "YES" : "NO", true, !analysis.CriticalObjectFound);
                    AddCellNum(analysis.NumberOfObjectsWithIndirect);
                    AddCellNum(analysis.MaximumIndirectNumber);
                    AddCellNum(analysis.MaximumDirectIndirectRatio);
                    break;
                }
                if (!found)
                {
                    AddCellNum(0, true);
                    AddCellNum(0, true);
                    AddCellNum(0, true);
                    AddCellNum(0, true);
                }
                AddEndRow();
            }
            AddEndTable();
        }

        private void GenerateCompromissionGraphDetailedAnalysis()
        {
            if (Report.ControlPaths.Data == null || Report.ControlPaths.Data.Count == 0)
                return;

            foreach (var typology in (CompromiseGraphDataTypology[])Enum.GetValues(typeof(CompromiseGraphDataTypology)))
            {
                var line = new Dictionary<int, SingleCompromiseGraphData>();
                for (int i = 0; i < Report.ControlPaths.Data.Count; i++)
                {
                    var data = Report.ControlPaths.Data[i];
                    if (data.Typology != typology)
                        continue;
                    line.Add(i, data);
                }

                if (line.Count == 0)
                    continue;

                GenerateSubSection(ReportHelper.GetEnumDescription(typology));
                AddParagraph("If the report has been saved which the full details, each object can be zoomed with its full detail. If it is not the case, for privacy reasons, only general statistics are available.");
                AddBeginTable("Summary of group");
                AddHeaderText("Group or user account", "The graph represents the objects which can take control of this group or user account.");
                AddHeaderText("Priority", "Indicates relatively to other objects the importance of this object when establishing a remediation plan. This importance is computed based on the impact and the easiness to proceed.");
                AddHeaderText("Users member", "Indicates the number of local user accounts that are members of this group. Foreign users or groups are excluded.");
                AddHeaderText("Computer member of the group", "Indicates the number of local computer accounts that are members of this group. Foreign users or groups are excluded.");
                AddHeaderText("Indirect control", "Indicates the number of local user or computer accounts that have indirect control over this object. Foreign users or groups are excluded.");
                AddHeaderText("Unresolved members", "Indicates the number of unresolved user or computer accounts. These accounts have most probably been deleted. Foreign users or groups are excluded.");
                AddHeaderText("Links", "Indicates the number of links with foreign domains aka foreign user or computer accounts.");
                AddHeaderText("Detail", "If available, open a modal which displays all the objects and their permissions in a map. This enables a quick understanding on how the figures have been collected.");
                AddBeginTableData();
                foreach (var i in line.Keys)
                {
                    GenerateSummary(i, line[i]);
                }
                AddEndTable();
            }

            for (int i = 0; i < Report.ControlPaths.Data.Count; i++)
            {
                GenerateModalGraph(i);
                GenerateUserModalMember(i);
                GenerateModalIndirectMember(i);
                GenerateModalDependancy(i);
                GenerateModalComputerMember(i);
                GenerateModalDeletedObjects(i);
            }
        }

        private void GenerateSummary(int index, SingleCompromiseGraphData data)
        {
            AddBeginRow();
            if (data.Nodes == null || data.Nodes.Count == 0)
            {
                AddCellText(data.Description);
            }
            else
            {
                Add(@"<td><a href=""#mcg-");
                Add(GenerateModalId(data.Description));
                Add(@""" data-bs-toggle=""modal"">");
                AddEncoded(data.Description);
                Add(@"</a></td>");
            }
            AddCellText(ReportHelper.GetEnumDescription(data.ObjectRisk));
            bool isAGroup = true;
            foreach (var node in data.Nodes)
            {
                if (node.Id == 0)
                {
                    if (node.Type != "group")
                        isAGroup = false;
                    break;
                }
            }
            if (isAGroup)
            {
                Add("<td class=\"num\">");
                Add(data.NumberOfDirectUserMembers);
                if (data.DirectUserMembers.Count > 0)
                {
                    Add(@" <a href=""#mod-member-");
                    Add(index);
                    Add(@""" data-bs-toggle=""modal"">");
                    Add("(Details)");
                    Add(@"</a>");
                }
                Add("</td>");

                Add("<td class=\"num\">");
                Add(data.NumberOfDirectComputerMembers);
                if (data.DirectComputerMembers.Count > 0)
                {
                    Add(@" <a href=""#mod-cmember-");
                    Add(index);
                    Add(@""" data-bs-toggle=""modal"">");
                    Add("(Details)");
                    Add(@"</a>");
                }
                Add("</td>");
            }
            else
            {
                AddCellNum(0, true);
                AddCellNum(0, true);
            }

            Add("<td class=\"num\">");
            Add(data.NumberOfIndirectMembers);
            if (data.CriticalObjectFound)
            {
                Add(" including <span class='unticked'>EVERYONE</span>");
            }
            if (data.IndirectMembers.Count > 0)
            {
                Add(@" <a href=""#mod-indirectmember-");
                Add(index);
                Add(@""" data-bs-toggle=""modal"">");
                Add("(Details)");
                Add(@"</a>");
            }
            Add("</td>");

            Add("<td class=\"num\">");
            Add(data.NumberOfDeletedObjects);
            if (data.DeletedObjects.Count != 0)
            {
                Add(@" <a href=""#mod-deleted-");
                Add(index);
                Add(@""" data-bs-toggle=""modal"">");
                Add("(Details)");
                Add(@"</a>");
            }
            Add("</td>");

            if (data.Dependancies.Count != 0)
            {
                Add("<td>");
                for (int i = 0; i < data.Dependancies.Count; i++)
                {
                    var d = data.Dependancies[i];
                    if (i > 0)
                        Add("<br>");
                    Add(@"<a href = ""#mod-dependancy-");
                    Add(index);
                    Add(@""" data-bs-toggle=""modal"">");
                    if (!String.IsNullOrEmpty(d.Netbios))
                    {
                        AddEncoded(d.Netbios);
                    }
                    else
                    {
                        Add("Unknown&nbsp;Domain&nbsp;");
                        Add(i);
                    }
                    Add("[");
                    Add(d.NumberOfResolvedItems);
                    Add("+");
                    Add(d.NumberOfUnresolvedItems);
                    Add("]</a>");
                }
                Add("</td>");
            }
            else
            {
                AddCellText(@"None");
            }
            if (data.Nodes == null || data.Nodes.Count == 0)
            {
                AddCellText("Not available");
            }
            else
            {
                Add(@"<td><a href=""#mcg-");
                Add(GenerateModalId(data.Description));
                Add(@""" data-bs-toggle=""modal"">Analysis");
                Add(@"</a></td>");
            }
            AddEndRow();
        }

        private void GenerateModalDependancy(int i)
        {
            AddBeginModal("mod-dependancy-" + i, Report.ControlPaths.Data[i].Description, ShowModalType.XL);
            foreach (var dependancy in Report.ControlPaths.Data[i].Dependancies)
            {
                Add(@"<h4>");
                if (!String.IsNullOrEmpty(dependancy.FQDN))
                {
                    AddEncoded(dependancy.FQDN);
                }
                else
                {
                    Add("Unknown&nbsp;Domain");
                }
                Add(@"</h4>");
                Add(@"<div class=""row""><div class=""col-lg-12""><dl class=""row"">
    <dt class=""col-sm-3"">NetBios</dt>
    <dd class=""col-sm-9"">");
                AddEncoded(dependancy.Netbios);
                Add(@"</dd>
    <dt class=""col-sm-3"">SID</dt>
    <dd class=""col-sm-9"">");
                AddEncoded(dependancy.Sid);
                Add(@"</dd>
  </dl></div></div>");
                if (dependancy.NumberOfResolvedItems > 0)
                {
                    Add(@"<h5>Resolved accounts (");
                    Add(dependancy.NumberOfResolvedItems);
                    Add(@")</h5>");
                    foreach (var account in dependancy.Items)
                    {
                        if (account.Sid != account.Name)
                        {
                            AddEncoded(account.Name);
                            Add(" (");
                            AddEncoded(account.Sid);
                            Add(")<br>");
                        }
                    }
                }
                if (dependancy.NumberOfUnresolvedItems > 0)
                {
                    Add(@"<h5>Unresolved accounts (");
                    Add(dependancy.NumberOfUnresolvedItems);
                    Add(@")</h5>");
                    foreach (var account in dependancy.Items)
                    {
                        if (account.Sid == account.Name)
                        {
                            AddEncoded(account.Sid);
                            Add("<br>");
                        }
                    }
                }
            }
            AddEndModal();
        }

        private void GenerateModalIndirectMember(int i)
        {
            AddBeginModal("mod-indirectmember-" + i, Report.ControlPaths.Data[i].Description, ShowModalType.XL);
            Add(@"<div class=""row""><div class=""col-lg-12""><h4>Indirect Members</h4></div></div>");
            AddBeginTable("Indirect member list");
            AddHeaderText("Name");
            AddHeaderText("Distance");
            AddHeaderText("Last authorized object");
            AddHeaderText("Path");
            AddBeginTableData();
            foreach (var member in Report.ControlPaths.Data[i].IndirectMembers)
            {
                DisplayIndirectMember(member);
            }
            AddEndTable();
            AddEndModal();
        }

        private void GenerateModalDeletedObjects(int i)
        {
            AddBeginModal("mod-deleted-" + i, Report.ControlPaths.Data[i].Description, ShowModalType.XL);
            Add(@"<div class=""row""><div class=""col-lg-12""><h4>Deleted objects</h4></div></div>");
            AddBeginTable("Deleted objects list");
            AddHeaderText("Security Identifier");
            AddBeginTableData();
            foreach (var member in Report.ControlPaths.Data[i].DeletedObjects)
            {
                AddBeginRow();
                AddCellText(member.Sid);
                AddEndRow();
            }
            AddEndTable();
            AddEndModal();
        }

        private void DisplayIndirectMember(SingleCompromiseGraphIndirectMemberData member)
        {
            AddBeginRow();
            if (!string.IsNullOrEmpty(member.Sid))
            {
                AddCellText(member.Name + @" (" + member.Sid + @")");
            }
            else
            {
                AddCellText(member.Name);
            }
            AddCellNum(member.Distance);
            AddCellText(member.AuthorizedObject);
            AddCellText(member.Path);
            AddEndRow();
        }

        private void GenerateUserModalMember(int i)
        {
            if (Report.ControlPaths.Data[i].DirectUserMembers == null || Report.ControlPaths.Data[i].DirectUserMembers.Count == 0)
                return;
            AddBeginModal("mod-member-" + i, Report.ControlPaths.Data[i].Description, ShowModalType.XL);
            Add(@"<div class=""row""><div class=""col-lg-12""><h4>Direct User Members</h4></div></div>");
            AddBeginTable("User list");
            AddHeaderText("SamAccountName");
            AddHeaderText("Enabled");
            AddHeaderText("Active");
            AddHeaderText("Pwd never Expired");
            AddHeaderText("Locked");
            AddHeaderText("Smart Card required");
            AddHeaderText("Service account");
            AddHeaderText("Flag Cannot be delegated present");
            AddHeaderText("Distinguished name");
            AddBeginTableData();
            foreach (var member in Report.ControlPaths.Data[i].DirectUserMembers)
            {
                DisplayUserMember(member);
            }
            AddEndTable();
            AddEndModal();
        }

        private void DisplayUserMember(SingleCompromiseGraphUserMemberData member)
        {
            AddBeginRow();
            AddCellText(member.Name);
            AddCellText(member.IsEnabled ? "YES" : "NO", true, member.IsEnabled);
            AddCellText(member.IsActive ? "YES" : "NO", true, member.IsActive);
            AddCellText(member.DoesPwdNeverExpires ? "YES" : "NO", true, !member.DoesPwdNeverExpires);
            AddCellText(member.IsLocked ? "YES" : "NO", true, !member.IsLocked);
            AddCellText(member.SmartCardRequired ? "YES" : "NO", member.SmartCardRequired, member.SmartCardRequired);
            AddCellText(member.IsService ? "YES" : "NO", member.IsService, !member.IsService);
            AddCellText(!member.CanBeDelegated ? "YES" : "NO", true, !member.CanBeDelegated);
            AddCellText(member.DistinguishedName);
            AddEndRow();
        }

        private void GenerateModalComputerMember(int i)
        {
            if (Report.ControlPaths.Data[i].DirectComputerMembers == null || Report.ControlPaths.Data[i].DirectComputerMembers.Count == 0)
                return;
            AddBeginModal("mod-cmember-" + i, Report.ControlPaths.Data[i].Description, ShowModalType.XL);
            Add(@"<div class=""row""><div class=""col-lg-12""><h4>Direct Computer Members</h4></div></div>");
            AddBeginTable("Computer list");
            AddHeaderText("SamAccountName");
            AddHeaderText("Enabled");
            AddHeaderText("Active");
            AddHeaderText("Locked");
            AddHeaderText("Flag Cannot be delegated present");
            AddHeaderText("Distinguished name");
            AddBeginTableData();
            foreach (var member in Report.ControlPaths.Data[i].DirectComputerMembers)
            {
                DisplayComputerMember(member);
            }
            AddEndTable();
            AddEndModal();
        }

        private void DisplayComputerMember(SingleCompromiseGraphComputerMemberData member)
        {
            AddBeginRow();
            AddCellText(member.Name);
            AddCellText(member.IsEnabled ? "YES" : "NO", true, member.IsEnabled);
            AddCellText(member.IsActive ? "YES" : "NO", true, member.IsActive);
            AddCellText(member.IsLocked ? "YES" : "NO", true, !member.IsLocked);
            AddCellText(!member.CanBeDelegated ? "YES" : "NO", true, !member.CanBeDelegated);
            AddCellText(member.DistinguishedName);
            AddEndRow();
        }

        private string GenerateModalId(string title)
        {
            return title.Replace(" ", "");
        }

        private void GenerateModalGraph(int i)
        {
            if (Report.ControlPaths.Data[i].Nodes == null || Report.ControlPaths.Data[i].Nodes.Count == 0)
                return;
            AddBeginModal("mcg-" + GenerateModalId(Report.ControlPaths.Data[i].Description), Report.ControlPaths.Data[i].Description, ShowModalType.FullScreen);
            Add(@"<div class=""progress mt-2 d-none"" id=""progress");
            Add(GenerateModalId(Report.ControlPaths.Data[i].Description));
            Add(@""">
					<div class=""progress-bar"" role=""progressbar"" aria-valuenow=""0"" aria-valuemin=""0"" aria-valuemax=""100"">
						0%
					</div>
				</div>
				<div id=""mynetwork");
            Add(GenerateModalId(Report.ControlPaths.Data[i].Description));
            Add(@""" class=""network-area""></div>

				<div class=""legend"">
					Legend: <br>
					<i class=""legend_user"">u</i> user<br>
					<i class=""legend_fsp"">w</i> external user or group<br>
					<i class=""legend_computer"">m</i> computer<br>
					<i class=""legend_group"">g</i> group<br>
					<i class=""legend_ou"">o</i> OU<br>
					<i class=""legend_gpo"">x</i> GPO<br>
					<i class=""legend_unknown"">?</i> Other<br>
					Settings: <br>
					<div class=""custom-control custom-switch"">
						<input type=""checkbox"" class=""custom-control-input"" checked id=""switch-1-");
            Add(GenerateModalId(Report.ControlPaths.Data[i].Description));
            Add(@""">
						<label class=""custom-control-label""  for=""switch-1-");
            Add(GenerateModalId(Report.ControlPaths.Data[i].Description));
            Add(@""">Compact display</label>
					</div>
					<div class=""custom-control custom-switch"">
						<input type=""checkbox"" class=""custom-control-input"" checked id=""switch-2-");
            Add(GenerateModalId(Report.ControlPaths.Data[i].Description));
            Add(@""">
						<label class=""custom-control-label""  for=""switch-2-");
            Add(GenerateModalId(Report.ControlPaths.Data[i].Description));
            Add(@""">Hierarchical view</label>
					</div>
				</div>
");
            AddEndModal(ShowModalType.FullScreen);
        }

        protected void GenerateCompromissionGraphJasonOutput()
        {
            for (int i = 0; i < Report.ControlPaths.Data.Count; i++)
            {
                AddLine(@"<script type=""application/json"" data-pingcastle-selector=""Data_" + GenerateModalId(Report.ControlPaths.Data[i].Description) + @""">");
                AddLine(BuildJasonFromSingleCompromiseGraph(Report.ControlPaths.Data[i]));
                AddLine("</script>");
            }
            AddLine(@"<script type=""application/json"" data-pingcastle-selector=""RelationTypeDescription"">");
            AddLine("{");
            bool first = true;
            foreach (var relationtype in (RelationType[])Enum.GetValues(typeof(RelationType)))
            {
                if (!first)
                    AddLine(",");
                else
                    first = false;
                var description = ReportHelper.GetEnumDescription(relationtype);
                Add("\"");
                AddJsonEncoded(relationtype.ToString());
                Add("\" : \"");
                AddJsonEncoded(description);
                Add("\"");
            }
            AddLine("}");
            AddLine("</script>");
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
                output.Append("      \"name\": \"" + ReportHelper.EscapeJsonString(node.Name) + "\",");
                output.Append("      \"type\": \"" + node.Type + "\",");
                output.Append("      \"shortName\": \"" + ReportHelper.EscapeJsonString(node.ShortName) + "\",");
                if (node.Suspicious)
                {
                    output.Append("      \"suspicious\": 1,");
                }
                if (node.Critical)
                {
                    output.Append("      \"critical\": 1,");
                }
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
                var hints = relation.Hints.Split(' ');
                for (int j = 0; j < hints.Length; j++)
                {
                    output.Append("         \"" + hints[j] + "\"" + (j == hints.Length - 1 ? String.Empty : ","));
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

        #endregion

        #region trust
        protected void GenerateTrustInformation()
        {
            List<string> knowndomains = new List<string>();
            AddParagraph("This section focuses on the relations that this domain has with other domains");
            GenerateSubSection("Discovered Domains", "discovereddomains");
            AddParagraph("This part displays the direct links that this domain has with other domains.");
            AddBeginTable("Trusts list");
            AddHeaderText("Trust Partner");
            AddHeaderText("Type");
            AddHeaderText("Attribut");
            AddHeaderText("Direction", @"<div class='text-start'><b>Bidirectional:</b> Each domain or forest has access to the resources of the other domain or forest. <br>
                <b>Inbound:</b> The other domain or forest has access to the resources of this domain or forest. This domain or forest does not have access to resources that belong to the other domain or forest. <br>
                <b>Outbound:</b> This domain or forest has access to resources of the other domain or forest. The other domain or forest does not have access to the resources of this domain or forest.</div>",
                true, true);
            AddHeaderText("SID Filtering active", @"<div class='text-start'>Indicates if the protection for the trust has been enabled or disabled.<br>
                A NO means that forged kerberos ticket with a security identifier from this domain will be accepted.<br>
                Please note that this check is being performed only at ONE direction of a BI-directional trust<br>
                Make sure you also run PingCastle in the Trust Partner domain for complete information</div>",
                true, true);
            AddHeaderText("TGT Delegation", @"<div class='text-start'>Indicates if the kerberos delegation works accross forest trusts<br>
                A YES means that TGTs are being sent over the trust<br>
                Please note that this check is being performed only at ONE direction of a BI-directional trust<br>Make sure you also run PingCastle in the Trust Partner domain for complete information</div>",
                true, true);
            AddHeaderText("Creation", "Indicates creation date of the underlying AD object");
            AddHeaderText("Is Active ?", "The account used to store the secret should be modified every 30 days if it is active. It indicates if a change occured during the last 40 days");
            if (Report.version >= new Version(2, 11))
            {
                AddHeaderText("Algorithm", "Indicates which algorithms are suitable for kerberos tickets signature");
            }
            AddBeginTableData();

            foreach (HealthCheckTrustData trust in Report.Trusts)
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
                    sidfiltering = "<span class=\"unticked\">" + sidfiltering + "</span>";
                }
                string tgtDelegation = TrustAnalyzer.GetTGTDelegation(trust);
                if (tgtDelegation == "Yes")
                {
                    tgtDelegation = "<span class=\"unticked\">" + tgtDelegation + "</span>";
                }
                else if (tgtDelegation == "No")
                {
                    tgtDelegation = "<span class=\"ticked\">" + tgtDelegation + "</span>";
                }
                AddBeginRow();
                Add(@"<td class='text'>");
                if (GetUrlCallbackDomain == null)
                {
                    AddEncoded(trust.TrustPartner);
                    AddBeginTooltip(html: true);
                    Add("SID: ");
                    Add(sid);
                    Add("<br>Netbios: ");
                    Add(netbios);
                    AddEndTooltip();
                }
                else
                {
                    Add(GetUrlCallbackDomain(trust.Domain, trust.TrustPartner, null));
                }
                Add(@"</td>");
                AddCellText(TrustAnalyzer.GetTrustType(trust.TrustType));
                AddCellText(TrustAnalyzer.GetTrustAttribute(trust.TrustAttributes));
                AddCellText(TrustAnalyzer.GetTrustDirection(trust.TrustDirection));
                Add("<td class='text'>");
                Add(sidfiltering);
                Add("</td><td class='text'>");
                Add(tgtDelegation);
                Add("</td>");
                AddCellDate(trust.CreationDate);
                AddCellText((trust.IsActive ? "TRUE" : "FALSE"), true, trust.IsActive);
                if (Report.version >= new Version(2, 11))
                {
                    if (trust.msDSSupportedEncryptionTypes == 0)
                    {
                        AddCellText("Default (RC4)");
                    }
                    else
                    {
                        Add("<td class='text'>");
                        Add(SupportedEncryptionTypeToString(trust.msDSSupportedEncryptionTypes));
                        Add("</td>");
                    }
                }
                AddEndRow();
            }
            AddEndTable();

            GenerateSubSection("Reachable Domains");
            AddParagraph("These are the domains that PingCastle was able to detect but which is not releated to direct trusts. It may be children of a forest or bastions.");
            AddBeginTable("Reachable domains list");
            AddHeaderText("Reachable domain");
            AddHeaderText("Discovered using");
            AddHeaderText("Netbios");
            AddHeaderText("Creation date");
            AddBeginTableData();

            foreach (HealthCheckTrustData trust in Report.Trusts)
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
                    AddBeginRow();
                    Add(@"<td class='text'>");
                    if (GetUrlCallbackDomain == null)
                    {
                        AddEncoded(di.DnsName);
                    }
                    else
                    {
                        Add(GetUrlCallbackDomain(di.Domain, di.DnsName, null));
                    }
                    Add(@"</td><td class='text'>");
                    if (GetUrlCallbackDomain == null)
                    {
                        AddEncoded(trust.TrustPartner);
                    }
                    else
                    {
                        Add(GetUrlCallbackDomain(trust.Domain, trust.TrustPartner, null));
                    }
                    Add(@"</td><td class='text'>");
                    AddEncoded(di.NetbiosName);
                    Add(@"</td><td class='text'>");
                    if (di.CreationDate == DateTime.MinValue)
                    {
                        Add("Unknown");
                    }
                    else
                    {
                        Add(di.CreationDate);
                    }
                    Add(@"</td>");
                    AddEndRow();
                }
            }
            if (Report.ReachableDomains != null)
            {
                foreach (HealthCheckTrustDomainInfoData di in Report.ReachableDomains)
                {
                    AddBeginRow();
                    Add(@"<td class='text'>");
                    if (GetUrlCallbackDomain == null)
                    {
                        AddEncoded(di.DnsName);
                    }
                    else
                    {
                        Add(GetUrlCallbackDomain(di.Domain, di.DnsName, null));
                    }
                    Add(@"</td>");
                    AddCellText("Unknown");
                    AddCellText(di.NetbiosName);
                    AddCellText("Unknown");
                    AddEndRow();
                }
            }

            AddEndTable();

            if (Report.AzureADSSOLastPwdChange != DateTime.MinValue)
            {
                GenerateSubSection("Azure", "azure");
                AddParagraph("The account AZUREADSSOACC is used under the hood to provide SSO functionalities with AzureAD.");
                Add(@"
		<div class=""row""><div class=""col-lg-12"">
<p>The password of the AZUREADSSOACC account should be changed twice every 40 days. You can check this <a href=""https://github.com/MicrosoftDocs/azure-docs/blob/main/articles/active-directory/hybrid/connect/tshoot-connect-sso.md"">documentation</a> to have the procedure.</p>
<p>You can use the version gathered using replication metadata from two reports to guess the frequency of the password change or if the two consecutive resets have been done. Version starts at 1.</p>
<p><strong>AZUREADSSOACC password last changed: </strong> " + Report.AzureADSSOLastPwdChange.ToString("u") + @"
<strong>version: </strong> " + Report.AzureADSSOVersion + @"
</p>
		</div></div>
");
            }

        }


        #endregion trust

        void AddGPOName(IGPOReference GPO)
        {
            if (GPO == null)
            {
                AddCellText("[null GPO]");
                return;
            }
            Add(@"<td class='text'>");
            AddEncoded(GPO.GPOName);
            if (!string.IsNullOrEmpty(GPO.GPOId))
            {
                if (!Report.GPOInfoDic.ContainsKey(GPO.GPOId))
                {
                    Add(@" <span class=""font-weight-light"">[Disabled]</span>");
                    Add("</td>");
                    return;
                }
                var refGPO = Report.GPOInfoDic[GPO.GPOId];
                if (refGPO == null)
                {
                    Add("[null GPO]</td>");
                    return;
                }
                if (refGPO.IsDisabled)
                {
                    Add(@" <span class=""font-weight-light"">[Disabled]</span>");
                }
                if (refGPO.AppliedTo != null && refGPO.AppliedTo.Count > 0)
                {
                    AddBeginTooltip(true, true);
                    Add("<div class='text-start'>Linked to:<br><ul>");
                    foreach (var i in refGPO.AppliedTo)
                    {
                        Add("<li>");
                        AddEncoded(i);
                        Add("</li>");
                    }
                    Add("</ul></div>");
                    Add("<div class='text-start'>Technical id:<br>");
                    AddEncoded(GPO.GPOId);
                    Add("</div>");
                    AddEndTooltip();
                }
                else
                {
                    Add(@" <span class=""font-weight-light"">[Not&nbsp;linked]</span>");
                    AddBeginTooltip(html: true);
                    Add("<div class='text-start'>Technical id:<br>");
                    AddEncoded(GPO.GPOId);
                    Add("</div>");
                    AddEndTooltip();
                }
            }
            Add("</td>");
        }

        #region infrastructure
        private void GenerateInfrastructureDetail()
        {
            GenerateAzureADConnect();
            GenerateWSUS();
            GenerateExchange();
            GenerateSCCM();
            GenerateServicePoints();
            if (Report.version >= new Version(2, 11))
            {
                GenerateAESPreparation();
            }
        }

        private void GenerateAzureADConnect()
        {
            if (Report.version >= new Version(2, 10, 1))
            {
                GenerateSubSection("Azure AD Connect settings");
                AddParagraph(@"Azure AD Connect help maintaining a synchronization between the Active Directory and Azure AD. Azure AD Connect servers should be considered as Tiers0 as they usually have the right to read the hashes of the user passwords.");
                AddBeginTable("Azure AD Connect account list");
                AddHeaderText("Identifier", "This is the technical identifier set by Microsoft to identify this connection");
                AddHeaderText("Computer", "This is the server where the synchronization is supposed to be performed");
                AddHeaderText("Tenant", "This is the tenant FQDN");
                AddHeaderText("IsEnabled", "Indicates if the account has not been disabled");
                AddHeaderText("Created", "The creation time of the MSOL account");
                AddHeaderText("LastLogon", "This is the last time the account has been used");
                AddHeaderText("PwdLastSet", "This is the last time the password of the account has been changed");
                AddHeaderText("Computer object found", "This indicates if the computer object associated with this account has been found or not");
                AddBeginTableData();
                if (Report.AzureADConnect != null)
                {
                    foreach (var a in Report.AzureADConnect)
                    {
                        AddBeginRow();
                        AddCellText(a.Identifier);
                        AddCellText(a.Computer);
                        AddCellText(a.Tenant);
                        AddCellText(a.MSOLIsEnabled ? "TRUE" : "FALSE", !a.MSOLIsEnabled);
                        AddCellText(a.MSOLCreated.ToString("u"));
                        AddCellText(a.MSOLLastLogon.ToString("u"), a.MSOLLastLogon.AddMonths(2) < DateTime.Now);
                        AddCellText(a.MSOLPwdLastSet.ToString("u"), a.MSOLPwdLastSet.AddMonths(2) < DateTime.Now);
                        var noComputer = string.IsNullOrEmpty(a.ComputerDN);
                        AddCellText(noComputer ? "FALSE" : "TRUE", noComputer);
                        AddEndRow();
                    }
                }
                AddEndTable();
            }
        }

        private void GenerateWSUS()
        {
            if (Report.version >= new Version(2, 10, 1))
            {
                GenerateSubSection("WSUS settings", "WSUSsettings");
                AddParagraph(@"WSUS settings allow workstations and servers located on the intranet to be updated. 
The <a href=""https://docs.microsoft.com/en-us/windows/deployment/update/waas-wu-settings"">reference documentation is here</a>. 
Here are the settings found in GPO.");
                AddBeginTable("WSUS settings list");
                AddHeaderText("Policy Name");
                AddHeaderText("WSUS Server", "This is the server that will distribute Windows Update inside the network");
                AddHeaderText("UseWUServer", "This option defines if the configuration is activated or ignored");
                AddHeaderText("ElevateNonAdmins", "This option specifies if normal users can disapprove updates");
                AddHeaderText("AUOptions", "This option determines if the local user can skip some updates");
                AddHeaderText("NoAutoUpdate", "This option disable the auto update behavior");
                AddHeaderText("NoAutoRebootWithLoggedOnUsers", "This option can block the update if there is a logged on user");
                AddBeginTableData();
                if (Report.GPOWSUS != null)
                {
                    foreach (var a in Report.GPOWSUS)
                    {
                        AddBeginRow();
                        AddGPOName(a);
                        AddCellText(a.WSUSserver);
                        AddCellText(GetAUOptionsText(a, "UseWUServer"));
                        AddCellText(GetAUOptionsText(a, "ElevateNonAdmins"));
                        AddCellText(GetAUOptionsText(a, "AUOptions"));
                        AddCellText(GetAUOptionsText(a, "NoAutoUpdate"));
                        AddCellText(GetAUOptionsText(a, "NoAutoRebootWithLoggedOnUsers"));
                        AddEndRow();
                    }
                }
                AddEndTable();
            }
        }

        string ExchangeSchemaToString(int version)
        {
            switch (version)
            {
                case 17003:
                    return "Exchange 2019 CU12";
                case 17002:
                    return "Exchange 2019 CU8";
                case 17001:
                    return "Exchange 2019 CU2";
                case 17000:
                    return "Exchange 2019 RTM";
                case 15334:
                    return "Exchange 2016 CU21";
                case 15333:
                    return "Exchange 2016 CU19";
                case 15332:
                    return "Exchange 2016 CU7";
                case 15330:
                    return "Exchange 2016 CU6";
                case 15326:
                    return "Exchange 2016 CU3";
                case 15325:
                    return "Exchange 2016 CU2";
                case 15323:
                    return "Exchange 2016 CU1";
                case 15317:
                    return "Exchange 2016 RTM";
                case 15312:
                    return "Exchange 2013 CU7";
                case 15303:
                    return "Exchange 2013 CU6";
                case 15300:
                    return "Exchange 2013 CU5";
                case 15292:
                    return "Exchange 2013 SP1 (CU4)";
                case 15283:
                    return "Exchange 2013 CU3";
                case 15281:
                    return "Exchange 2013 CU2";
                case 15254:
                    return "Exchange 2013 CU1";
                case 15137:
                    return "Exchange 2013 RTM";
                case 14734:
                    return "Exchange 2010 SP3";
                case 14732:
                    return "Exchange 2010 SP2";
                case 14726:
                    return "Exchange 2010 SP1";
                case 14625:
                    return "Exchange 2007 SP3";
                case 14622:
                    return "Exchange 2007 SP2";
                case 11116:
                    return "Exchange 2007 SP1";
                case 10637:
                    return "Exchange 2007 RTM";
                case 6870:
                    return "Exchange 2003 RTM";
                case 4406:
                    return "Exchange 2000 SP2";
                case 4397:
                    return "Exchange 2000 RTM";
                default:
                    return "Unknown (" + version + ") - check out https://www.alitajran.com/exchange-schema-versions/";
            }
        }

        private void GenerateExchange()
        {
            if (Report.version >= new Version(2, 11, 1))
            {
                GenerateSubSection("Exchange settings", "Exchangesettings");
                AddParagraph(@"Echange is the mail server of Microsoft. Because it is deeply integrated into the Active Directory, it is a component to be monitored");
                AddParagraph("PingCastle is checking objects of type msExchExchangeServer and the schema to provide the information below.");
                if (Report.ExchangeInstall != default(DateTime))
                {
                    Add("Since recent version, Exchange allows information to be stored in the Active Directory Schema to perform offline configuration. It is a copy of some information stored locally on the servers");
                    Add(@"
		<div class=""row""><div class=""col-lg-12"">
<p><strong>Exchange schema installation:</strong> " + Report.ExchangeInstall.ToString("u") + @"</p>
		</div></div>
");
                }
                if (Report.ExchangeSchemaVersion > 0)
                {
                    Add(@"
		<div class=""row""><div class=""col-lg-12"">
<p><strong>The Exchange schema version is :</strong> " + ExchangeSchemaToString(Report.ExchangeSchemaVersion) + @"</p>
		</div></div>
");
                }
                AddBeginTable("Exchange servers");
                AddHeaderText("Name");
                AddHeaderText("In service date");
                AddHeaderText("Version");
                AddHeaderText("Proxy");
                AddBeginTableData();
                if (Report.ExchangeServers != null)
                {
                    foreach (var a in Report.ExchangeServers)
                    {
                        AddBeginRow();
                        AddCellText(a.Name);
                        AddCellDate(a.CreationDate);
                        AddCellText(a.SerialNumber);
                        AddCellText(a.InternetWebProxy);
                        AddEndRow();
                    }
                }
                AddEndTable();
            }
        }

        private void GenerateSCCM()
        {
            if (Report.version >= new Version(2, 11, 0))
            {
                GenerateSubSection("SCCM settings", "SCCMsettings");
                AddParagraph(@"SCCM or its more recent name Microsoft Endpoint Manager is the Microsoft tool to manage the workstations and servers. It is used typically to deploy packages.");
                AddParagraph("PingCastle is checking objects of type mSSMSManagementPoint and the schema to provide the information below.");
                if (Report.SCCMInstalled != default(DateTime))
                {
                    Add(@"
		<div class=""row""><div class=""col-lg-12"">
<p><strong>SCCM has been installed for the first time at:</strong> " + Report.SCCMInstalled.ToString("u") + @"</p>
		</div></div>
");
                }

                AddBeginTable("SCCM servers");
                AddHeaderText("Name");
                AddHeaderText("Version");
                AddHeaderText("Client operational version");
                AddHeaderText("AAD TenantID");
                AddHeaderText("AAD TenantName");
                AddBeginTableData();
                if (Report.SCCMServers != null)
                {
                    foreach (var a in Report.SCCMServers)
                    {
                        string version = null;
                        string tenantID = null;
                        string tenantName = null;
                        if (!string.IsNullOrEmpty(a.Capabilities))
                        {
                            XmlDocument doc = new XmlDocument();
                            doc.LoadXml(a.Capabilities);
                            var node = doc.SelectSingleNode(@"//ClientOperationalSettings/Version");
                            if (node != null)
                                version = node.InnerText;

                            node = doc.SelectSingleNode(@"//ClientOperationalSettings/AADConfig/Tenants/Tenant");
                            if (node != null)
                            {
                                foreach (XmlAttribute b in node.Attributes)
                                {
                                    if (b.Name == "ID")
                                        tenantID = b.Value;
                                    else if (b.Name == "Name")
                                        tenantName = b.Value;
                                }
                            }
                        }
                        AddBeginRow();
                        AddCellText(a.MPName);
                        AddCellNum(a.Version);
                        AddCellText(version);
                        AddCellText(tenantID);
                        AddCellText(tenantName);
                        AddEndRow();
                    }
                }
                AddEndTable();
            }
        }

        private void GenerateServicePoints()
        {
            if (Report.version >= new Version(2, 10, 1))
            {
                GenerateSubSection("Service Connection Points", "servicePoints");
                AddParagraph(@"Service Connection Points are a configuration stored in the AD to expose services to all computers.");
                AddBeginTable("Service Connection Points list");
                AddHeaderText("Service", "This value is guessed by PingCastle based on well known class names");
                AddHeaderText("Class", "This is the value of the property ServiceClassName");
                AddHeaderText("DNS", "This is the value of the property ServiceDNSName");
                AddHeaderText("Binding Info", "The value used to establish the connection. Its meaning is on a per class basis");
                AddHeaderText("DN", "This is the location of the object in the AD");
                AddBeginTableData();
                if (Report.ServicePoints != null)
                {
                    var spref = new Dictionary<string, string>
                    {
                        {"BEMainService", "BackupExec server"},
                        {"Novel", "Novell Groupwise"},
                        {"7802DE87-9F23-4DAB-A31D-7991A4F11625", "Novell Groupwise"},
                        {"FB6F0931-1D3A-4C36-8F97-EC97636138DD", "Novell Groupwise"},
                        {"Groupwise", "Novell Groupwise"},
                        {"ldap", "AD LDS"},
                        {"LDAP", "AD LDS"},
                        {"TSGateway", "RDS Gateway"},
                        {"ms-Exchange-AutoDiscover-Service", "Exchange Autodiscover"},
                        {"", ""},
                    };
                    foreach (var a in Report.ServicePoints)
                    {
                        AddBeginRow();
                        if (spref.ContainsKey(a.ClassName))
                        {
                            AddCellText(spref[a.ClassName]);
                        }
                        else
                        {
                            AddCellText(null);
                        }
                        AddCellText(a.ClassName);
                        AddCellText(a.DNS);
                        string bindingInfo = null;
                        if (a.BindingInfo != null)
                        {
                            bindingInfo = string.Join("\r\n", a.BindingInfo.ToArray());
                        }
                        AddCellText(bindingInfo);
                        AddCellText(a.DN);
                        AddEndRow();
                    }
                }
                AddEndTable();
            }
        }

        private void GenerateAESPreparation()
        {
            GenerateSubSection("Replacement of RC4 by AES in kerberos");
            AddParagraph(@"This section checks for known pain points in AES activation and RC4 removal for kerberos");
            bool OK;
            if (_license.IsBasic())
            {
                AddParagraph("This feature is reserved for customers who have <a href='https://www.pingcastle.com/services/'>purchased a license</a>");
                return;
            }
            if (Report.DCWin2008Install == default(DateTime))
            {
                AddParagraph("PingCastle could not determine the creation date of the group 'Read-Only Domain Controllers'. As a consequence, it cannot evaluate the AES section");
                return;
            }
            AddParagraph("This section is here to evaluate the know problems when removing RC4. If you plan to do so, you should check all the items highlighted below and proceed with a small group of test computers.");
            AddParagraph("Please see the following articles:");
            AddListStart();
            AddLink("https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/decrypting-the-selection-of-supported-kerberos-encryption-types/ba-p/1628797");
            AddListContinue();
            AddLink("https://docs.microsoft.com/en-us/archive/blogs/openspecification/encryption-type-selection-in-kerberos-exchanges");
            AddListContinue();
            AddLink("https://docs.microsoft.com/en-us/archive/blogs/openspecification/windows-configurations-for-kerberos-supported-encryption-typ");
            AddListContinue();
            AddLink("https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/the-rc4-removal-files-part-2-in-aes-we-trust/ba-p/1029439");
            AddListContinue();
            AddLink("https://docs.microsoft.com/en-us/archive/blogs/openspecification/msds-supportedencryptiontypes-episode-1-computer-accounts");
            AddListContinue();
            AddLink("https://docs.microsoft.com/en-us/windows-server/security/kerberos/preventing-kerberos-change-password-that-uses-rc4-secret-keys");
            AddListContinue();
            AddLink("https://syfuhs.net/lessons-in-disabling-rc4-in-active-directory");
            AddListEnd();
            AddParagraph("This program will proceed to know:");
            AddListStart();
            Add("That the infrastructure is compatible with AES. It will asserts that all client accounts have an AES hash.");
            AddListContinue();
            Add("That all services (trust, ...) can accept AES kerberos tickets. This is done by checking the special attribute msDS-SupportedEncryptionTypes.");
            AddListContinue();
            Add("That the AES algorithm is pushed to the client by GPO. This is done by looking at the setting 'Configure encryption types allowed for Kerberos'.");
            AddListEnd();
            Add("<h3>Infrastructure</h3>");
            AddParagraph("This program starts by determining for how long the infrastructure in place is compatible with AES.");
            AddParagraph("This is done by retrieving the creation date of the groupe 'Read-Only Domain Controllers' which is linked to the first DC compatible with AES (Windows Server 2008).");
            Add(@"
		<div class=""row""><div class=""col-lg-12"">
<p><strong>Installation date of the first DC compatible with AES: </strong> " + Report.DCWin2008Install.ToString("u") + @"</p>
		</div></div>
");
            AddParagraph("All passwords saved after this date have their hash saved with both RC4 and AES.");
            // all DC > 2003
            Add("<h3>Krbtgt</h3>");
            AddParagraph("To issue Kerberos ticket, the krbtgt account holding the kerberos secret key must have a password changed AFTER the installation of the first DC compatible with AES.");
            OK = Report.KrbtgtLastChangeDate >= Report.DCWin2008Install;
            Add(@"
		<div class=""row""><div class=""col-lg-12"">
<p><strong>Last krbtgt change: </strong> " + Report.KrbtgtLastChangeDate.ToString("u") + @"</p>
<p>" + (OK ? "<span class='ticked'>OK</span>" : "<span class='unticked'>Not OK</span>") + @"</p>
		</div></div>
");
            Add("<h3>Domain Controllers</h3>");
            AddParagraph("To support AES, all DC must be at least Windows 2008.");
            AddBeginTable("DC OS list for AES");
            AddHeaderText("Domain Controller");
            AddHeaderText("OS");
            AddHeaderText("AES compatible");
            AddBeginTableData();
            OK = true;
            foreach (var dc in Report.DomainControllers)
            {
                AddBeginRow();
                AddCellText(dc.DCName);
                AddCellText(dc.OperatingSystem);
                if (!(dc.OperatingSystem == "Windows 2000" || dc.OperatingSystem == "Windows 2003"))
                {
                    AddCellText("Yes", true, true);
                }
                else
                {
                    AddCellText("No", true, false);
                    OK = false;
                }
                AddEndRow();
            }
            AddEndTable();
            Add("<p>" + (OK ? "<span class='ticked'>OK</span>" : "<span class='unticked'>Not OK</span>") + @"</p>");
            Add("<h3>Trusts</h3>");
            OK = true;
            AddParagraph("To be used over trusts, AES requires the trust to support this algorithm. This is done thought the special attribute msDS-SupportedEncryptionTypes.");
            AddParagraph("Be aware that checking 'The other domain supports Kerberos AES Encryption' in the trust property disables RC4. This check is not recommended during the migration phase.");
            if (Report.Trusts == null || Report.Trusts.Count == 0)
            {
                AddParagraph("No trust detected");
            }
            else
            {
                AddBeginTable("Trusts list for AES");
                AddHeaderText("Trust Partner");
                AddHeaderText("Creation", "Indicates creation date of the underlying AD object");
                AddHeaderText("Is Active ?", "The account used to store the secret should be modified every 30 days if it is active. It indicates if a change occured during the last 40 days");
                AddHeaderText("Algorithm", "Indicates which algorithms are suitable for kerberos tickets signature");
                AddHeaderText("AES compatible");
                AddBeginTableData();

                foreach (HealthCheckTrustData trust in Report.Trusts)
                {
                    string sid = (string.IsNullOrEmpty(trust.SID) ? "[Unknown]" : trust.SID);
                    string netbios = (string.IsNullOrEmpty(trust.NetBiosName) ? "[Unknown]" : trust.NetBiosName);

                    AddBeginRow();
                    Add(@"<td class='text'>");
                    if (GetUrlCallbackDomain == null)
                    {
                        AddEncoded(trust.TrustPartner);
                        AddBeginTooltip(html: true);
                        Add("SID: ");
                        Add(sid);
                        Add("<br>Netbios: ");
                        Add(netbios);
                        AddEndTooltip();
                    }
                    else
                    {
                        Add(GetUrlCallbackDomain(trust.Domain, trust.TrustPartner, null));
                    }
                    Add(@"</td>");
                    AddCellDate(trust.CreationDate);
                    AddCellText((trust.IsActive ? "TRUE" : "FALSE"), true, trust.IsActive);
                    if (trust.msDSSupportedEncryptionTypes == 0)
                    {
                        AddCellText("Default (RC4)");
                    }
                    else
                    {
                        Add("<td class='text'>");
                        Add(SupportedEncryptionTypeToString(trust.msDSSupportedEncryptionTypes));
                        Add("</td>");
                    }
                    var aescompatible = (trust.msDSSupportedEncryptionTypes & (8 + 16)) != 0;
                    if (aescompatible)
                    {
                        AddCellText("Yes", true, true);
                    }
                    else
                    {
                        AddCellText("No", true, false);
                        OK = false;
                    }
                    AddEndRow();
                }
                AddEndTable();
            }
            Add("<p>" + (OK ? "<span class='ticked'>OK</span>" : "<span class='unticked'>Not OK</span>") + @"</p>");

            Add("<h3>Azure</h3>");
            OK = true;
            AddParagraph("To be used over Azure, the special AzureSSO account must be setup to support AES.");
            if (Report.AzureADSSOLastPwdChange == DateTime.MinValue)
            {
                AddParagraph("No AzureAD SSO detected");
            }
            else
            {
                Add(@"
		<div class=""row""><div class=""col-lg-12"">
<p><strong>Algorithm supported for AzureAD SSO: </strong> " + SupportedEncryptionTypeToString(Report.AzureADSSOEncryptionType) + @"</p>
		</div></div>
");
                var aescompatible = (Report.AzureADSSOEncryptionType & (8 + 16)) != 0;
                OK = aescompatible;
            }
            Add("<p>" + (OK ? "<span class='ticked'>OK</span>" : "<span class='unticked'>Not OK</span>") + @"</p>");

            Add("<h3>Service accounts</h3>");
            AddParagraph(@"Kerberos tickets for services are signed by the password hash of the service account.
            The service account must be declared as compatible to handle AES. This is done through the special attribute named msDS-SupportedEncryptionTypes or by checking 'This account supports Kerberos AES XXX bit encryption' in the account properties.");
            AddParagraph("The service account must also have a password newer than the first DC compatible with AES. If there was no password change, the creation date must be newer than the first DC compatible with AES.");
            AddParagraph("If a service account is not compatible, you will received error messages like 'The encryption type requested is not supported by the KDC'. See the following KB for SharePoint of SCCM errors:");
            AddListStart();
            AddLink("https://docs.microsoft.com/en-us/sharepoint/troubleshoot/security/configuration-to-support-kerberos-aes-encryption");
            AddListContinue();
            AddLink("https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/sccm-quot-the-encryption-type-requested-is-not-supported-by-the/ba-p/570914");
            AddListEnd();

            Add("<p><strong>Number of service account found without AES configuration: </strong> " + (Report.UserAccountData.NumberNotAesEnabled + Report.ComputerAccountData.NumberNotAesEnabled) + @"</p>");

            if ((Report.UserAccountData.ListNotAesEnabled != null && Report.UserAccountData.ListNotAesEnabled.Count > 0) || (Report.ComputerAccountData.ListNotAesEnabled != null && Report.ComputerAccountData.ListNotAesEnabled.Count > 0))
            {
                var list = new List<HealthcheckAccountDetailData>();
                if (Report.UserAccountData.ListNotAesEnabled != null)
                    list.AddRange(Report.UserAccountData.ListNotAesEnabled);
                if (Report.ComputerAccountData.ListNotAesEnabled != null)
                    list.AddRange(Report.ComputerAccountData.ListNotAesEnabled);
                GenerateAccordion("globalNotAesEnabled", () => GenerateListAccountDetail("globalNotAesEnabled", "globalNotAesEnabledpanel", "Accounts with a SPN but without AES declared as supported or having a password not compatible with AES", list));
            }

            OK = (Report.UserAccountData.NumberNotAesEnabled + Report.ComputerAccountData.NumberNotAesEnabled) == 0;
            Add("<p>" + (OK ? "<span class='ticked'>OK</span>" : "<span class='unticked'>Not OK</span>") + @"</p>");
            // gpo
            Add("<h3>GPO to set encryption</h3>");
            AddParagraph("The algorithm to use for kerberos request is decided by a local GPO which is overwritten by domain GPO.");
            AddParagraph("Here is the list of domain GPO altering the kerberos algorithms");

            OK = true;
            bool found = false;

            AddBeginTable("Trusts list for AES");
            AddHeaderText("Policy Name");
            AddHeaderText("Algorithm", "Indicates which algorithms are suitable for kerberos tickets signature");
            AddHeaderText("AES compatible");
            AddHeaderText("RC4 compatible");
            AddBeginTableData();
            foreach (var policy in Report.GPOLsaPolicy)
            {
                foreach (var property in policy.Properties)
                {
                    if (property.Property == "SupportedEncryptionTypes")
                    {
                        found = true;
                        AddBeginRow();
                        AddGPOName(policy);
                        AddLsaSettingsValue(property.Property, property.Value);
                        var aescompatible = (property.Value & (8 + 16)) != 0;
                        if (aescompatible)
                        {
                            AddCellText("Yes", true, true);
                        }
                        else
                        {
                            AddCellText("No", true, false);
                            OK = false;
                        }
                        var rc4compatible = (property.Value & (4)) != 0;
                        if (rc4compatible)
                        {
                            AddCellText("Yes");
                        }
                        else
                        {
                            AddCellText("No", true, true);
                        }
                        AddEndRow();
                    }
                }
            }
            AddEndTable();
            Add("<p>" + (OK ? "<span class='ticked'>OK</span>" : "<span class='unticked'>Not OK</span>") + @"</p>");
            if (!found)
            {
                AddParagraph("Beware that no GPO supporting AES / RC4 have been found and if the supported algorithm is not defined in the master, AES will not be enabled by default");
            }
        }

        #endregion infrastructure

        #region anomaly
        protected void GenerateAnomalyDetail()
        {
            AddParagraph("This section focuses on security checks specific to the Active Directory environment.");
            GenerateSubSection("Backup", "backup");
            Add(@"
		<div class=""row""><div class=""col-lg-12"">
<p>The program checks the last date of the AD backup. This date is computed using the replication metadata of the attribute dsaSignature (<a href=""https://technet.microsoft.com/en-us/library/jj130668(v=ws.10).aspx"">reference</a>).</p>
<p><strong>Last backup date: </strong> " + (Report.LastADBackup == DateTime.MaxValue ? "<span class=\"unticked\">Never</span>" : (Report.LastADBackup == DateTime.MinValue ? "<span class=\"unticked\">Not checked (older version of PingCastle)</span>" : Report.LastADBackup.ToString("u"))) + @"</p>
		</div></div>
");

            GenerateSubSection("LAPS", "laps");
            Add(@"
		<div class=""row""><div class=""col-lg-12"">
<p><a href=""https://support.microsoft.com/en-us/kb/3062591"">LAPS</a> is used to have a unique local administrator password on all workstations / servers of the domain.
Then this password is changed at a fixed interval. The risk is when a local administrator hash is retrieved and used on other workstation in a pass-the-hash attack.
Please note that the LAPS schema is installed on the forest and as a consequence the installation date can be before the domain creation date.</p>
<p>Mitigation: having a process when a new workstation is created or install LAPS and apply it through a GPO</p>
<p><strong>Legacy LAPS installation date: </strong> " + (Report.LAPSInstalled == DateTime.MaxValue ? "<span class=\"unticked\">Never</span>" : (Report.LAPSInstalled == DateTime.MinValue ? "<span class=\"unticked\">Not checked (older version of PingCastle)</span>" : Report.LAPSInstalled.ToString("u"))) + @"</p>
<p><strong>Ms LAPS installation date: </strong> " + (Report.NewLAPSInstalled == DateTime.MaxValue ? "<span class=\"unticked\">Never</span>" : (Report.NewLAPSInstalled == DateTime.MinValue ? "<span class=\"unticked\">Not checked (older version of PingCastle)</span>" : Report.NewLAPSInstalled.ToString("u"))) + @"</p>
		</div></div>
");
            if (Report.ListLAPSJoinedComputersToReview != null && Report.ListLAPSJoinedComputersToReview.Count > 0)
            {
                AddParagraph("Here is the list of computers joined to the domain by users who have access to the LAPS password (or can modify the security to see it). This program looks if the mS-DS-CreatorSID is found: on the owner or on security permissions such as write owner, write security descriptor and all extended rights.");
                GenerateAccordion("lapscreatedsid", () => GenerateListAccountDetail("lapscreatedsid", "lapscreatedsidpanel", "Computers joined to the domain by a user who has now access to their LAPS password", Report.ListLAPSJoinedComputersToReview));
            }

            GenerateSubSection("Windows Event Forwarding (WEF)");
            Add(@"
		<div class=""row""><div class=""col-lg-12"">
<p>Windows Event Forwarding is a native mechanism used to collect logs on all workstations / servers of the domain.
Microsoft recommends to <a href=""https://docs.microsoft.com/en-us/windows/threat-protection/use-windows-event-forwarding-to-assist-in-instrusion-detection"">Use Windows Event Forwarding to help with intrusion detection</a>
Here is the list of servers configured for WEF found in GPO</p>
<p><strong>Number of WEF configuration found: </strong> " + (Report.GPOEventForwarding.Count) + @"</p>
		</div></div>
");
            // wef
            if (Report.GPOEventForwarding.Count > 0)
            {
                Add(@"
		<div class=""row"">
			<div class=""col-md-12"">");
                GenerateAccordion("wef", () =>
                    {
                        GenerateAccordionDetailForDetail("wefPanel", "wef", "Windows Event Forwarding servers", Report.GPOEventForwarding.Count, () =>
                            {
                                AddBeginTable("WEF list");
                                AddHeaderText("GPO Name");
                                AddHeaderText("Order");
                                AddHeaderText("Server");
                                AddBeginTableData();

                                // descending sort
                                Report.GPOEventForwarding.Sort(
                                    (GPOEventForwardingInfo a, GPOEventForwardingInfo b)
                                        =>
                                    {
                                        int comp = String.Compare(a.GPOName, b.GPOName);
                                        if (comp == 0)
                                            comp = (a.Order > b.Order ? 1 : (a.Order == b.Order ? 0 : -1));
                                        return comp;
                                    }
                                    );

                                foreach (var info in Report.GPOEventForwarding)
                                {
                                    AddBeginRow();
                                    AddCellText(info.GPOName);
                                    AddCellNum(info.Order);
                                    AddCellText(info.Server);
                                    AddEndRow();
                                }
                                AddEndTable();
                            });
                    });
                Add(@"
			</div>
		</div>
");
            }


            // krbtgt
            GenerateSubSection("krbtgt (Used for Golden ticket attacks)", "krbtgt");
            Add(@"
		<div class=""row""><div class=""col-lg-12"">
<p>The account password for the <em>krbtgt</em> account should be rotated twice yearly at a minimum. More frequent password rotations are recommended, with 40 days the current recommendation by ANSSI. Additional rotations based on external events, such as departure of an employee who had privileged network access, are also strongly recommended.</p>
<p>You can perform this action using this <a href=""https://github.com/microsoft/New-KrbtgtKeys.ps1"">script</a></p>
<p>You can use the version gathered using replication metadata from two reports to guess the frequency of the password change or if the two consecutive resets have been done. Version starts at 1.</p>
<p><strong>Kerberos password last changed: </strong> " + Report.KrbtgtLastChangeDate.ToString("u") + @"
<strong>version: </strong> " + Report.KrbtgtLastVersion + @"
</p>
		</div></div>
");
            // adminSDHolder
            GenerateSubSection("AdminSDHolder (detect temporary elevated accounts)", "admincountequalsone");
            Add(@"
		<div class=""row""><div class=""col-lg-12"">
<p>This control detects accounts which are former 'unofficial' admins.
Indeed when an account belongs to a privileged group, the attribute admincount is set. If the attribute is set without being an official member, this is suspicious. To suppress this warning, the attribute admincount of these accounts should be removed after review.</p>
<p><strong>Number of accounts to review:</strong> " +
        (Report.AdminSDHolderNotOKCount > 0 ? "<span class=\"unticked\">" + Report.AdminSDHolderNotOKCount + "</span>" : "0")
    + @"</p>
		</div></div>
");
            if (Report.AdminSDHolderNotOKCount > 0 && Report.AdminSDHolderNotOK != null && Report.AdminSDHolderNotOK.Count > 0)
            {
                GenerateAccordion("adminsdholder", () => GenerateListAccountDetail("adminsdholder", "adminsdholderpanel", "AdminSDHolder User List", Report.AdminSDHolderNotOK));
            }

            // unix user password
            GenerateSubSection("Unix Passwords", "unixpasswordsfound");
            Add(@"
		<div class=""row""><div class=""col-lg-12"">
<p>This control detects if one of the attributes userPassword or unixUserPassword has been set on accounts.
Indeed, these attributes are designed to store encrypted secrets for unix (or mainframe) interconnection. However in the large majority, interconnected systems are poorly designed and the user password is stored in these attributes in clear text or poorly encrypted.
The userPassword attribute is also used in classic LDAP systems to change the user password by setting its value. But, with Active Directory, it is considered by default as a normal attribute and doesn't trigger a password but shows instead the password in clear text.
</p>
<p><strong>Number of accounts to review:</strong> " +
        (Report.UnixPasswordUsersCount > 0 ? "<span class=\"unticked\">" + Report.UnixPasswordUsersCount + "</span>" : "0")
    + @"</p>
		</div></div>
");
            if (Report.UnixPasswordUsersCount > 0 && Report.UnixPasswordUsers != null && Report.UnixPasswordUsers.Count > 0)
            {
                GenerateAccordion("unixpasswords", () => GenerateListAccountDetail("unixpasswords", "unixpasswordspanel", "User List With Unix Passwords", Report.UnixPasswordUsers));
            }

            // java code reference
            if (Report.version >= new Version(2, 10, 1))
            {
                GenerateSubSection("Java code reference", "javacoderefence");
                Add(@"
		<div class=""row""><div class=""col-lg-12"">
<p>This control detects if one of the attributes javaCodebase, javaFactory or javaClassname has been set on accounts.
Indeed, these attributes are designed to add custom code to AD object when running java code. However it can be abused to run code on servers having the flag com.sun.jndi.ldap.object.trustURLCodebase set to true.
This is a vulnerability similar to the log4shell vulnerability.</p>
<p><strong>Java Schema extension:</strong> " +
            (Report.JavaClassFound ? "<span class=\"unticked\">Found</span>" : "Not Found")
        + @"</p>
		</div></div>
");
                if (Report.JavaClassFound && Report.JavaClassFoundDetail != null && Report.JavaClassFoundDetail.Count > 0)
                {
                    GenerateAccordion("javacoderefencedetails", () => GenerateListAccountDetail("javacoderefencedetails", "javacoderefencedetailspanel", "User object with custom javacode", Report.JavaClassFoundDetail));
                }
                else
                {
                    AddParagraph("No active user account found with Java code");
                }
            }

            if (Report.DomainControllers != null)
            {
                int countnullsession = 0;
                foreach (var DC in Report.DomainControllers)
                {
                    if (DC.HasNullSession)
                    {
                        countnullsession++;
                    }
                }
                if (countnullsession > 0)
                {
                    GenerateSubSection("NULL SESSION (anonymous access)", "nullsession");
                    Add(@"
		<div class=""row""><div class=""col-lg-12"">
<p>This control detects domain controllers which can be accessed without authentication.
Hackers can then perform a reconnaissance of the environement with only a network connectivity and no account at all.</p>
			<p><strong>Domain controllers vulnerable:</strong> <span class=""unticked"">" + countnullsession + @"</span>
		</div></div>
		<div class=""row"">
			<div class=""col-md-12"">
");
                    GenerateAccordion("nullsessions", () =>
                        {
                            GenerateAccordionDetailForDetail("nullsessionPanel", "nullsessions", "Domain controllers with NULL SESSION Enabled", countnullsession, () =>
                                {
                                    AddBeginTable("Null session list");
                                    AddHeaderText("Domain Controller");
                                    AddBeginTableData();
                                    foreach (var DC in Report.DomainControllers)
                                    {
                                        if (DC.HasNullSession)
                                        {
                                            AddBeginRow();
                                            AddCellText(DC.DCName);
                                            AddEndRow();
                                        }
                                    }
                                    AddEndTable();
                                }
                            );
                        }
                    );
                    Add(@"
			</div>
		</div>
");
                }

                if (Report.SmartCardNotOK != null && Report.SmartCardNotOK.Count > 0)
                {
                    // smart card
                    GenerateSubSection("Smart Card and Password", "smartcardmandatorywithnopasswordchange");
                    Add(@"
		<div class=""row""><div class=""col-lg-12"">
<p>This control detects users which use only smart card and whose password hash has not been changed for at least 90 days.
Indeed, once the smart card required check is activated in the user account properties, a random password hash is set.
But this hash is not changed anymore like for users having a password whose change is controlled by password policies.
As a consequence, a capture of the hash using a memory attack tool can lead to a compromise of this account unlimited in time.
The best practice is to reset these passwords on a regular basis or to uncheck and check again the &quot;require smart card&quot; property to force a hash change.</p>
			<p><strong>Users with smart card and having their password unchanged since at least 90 days:</strong> " +
        (Report.SmartCardNotOK == null ? 0 : Report.SmartCardNotOK.Count)
        + @"</p>
		</div></div>
");
                    GenerateAccordion("anomalysmartcard", () => GenerateListAccountDetail("anomalysmartcard", "smartcard", "Smart card and Password >90 days List", Report.SmartCardNotOK));
                }

                // logon script
                GenerateSubSection("Logon scripts", "logonscripts");
                AddParagraph("You can check here for backdoors or typos in the scriptPath attribute");
                AddBeginTable("Logon script list");
                AddHeaderText("Script Name");
                AddHeaderText("Count");
                AddBeginTableData();
                // descending sort
                Report.LoginScript.Sort(
                    (HealthcheckLoginScriptData a, HealthcheckLoginScriptData b)
                        =>
                    {
                        return b.NumberOfOccurence.CompareTo(a.NumberOfOccurence);
                    }
                    );

                int number = 0;
                foreach (HealthcheckLoginScriptData script in Report.LoginScript)
                {
                    AddBeginRow();
                    AddCellText(String.IsNullOrEmpty(script.LoginScript.Trim()) ? "<spaces>" : script.LoginScript);
                    AddCellNum(script.NumberOfOccurence);
                    AddEndRow();
                    number++;
                    if (number >= MaxNumberUsersInHtmlReport)
                    {
                        break;
                    }
                }
                Add(@"
				</tbody>");
                if (number >= MaxNumberUsersInHtmlReport)
                {
                    Add("<tfoot><tr><td colspan='2' class='text'>Output limited to ");
                    Add(MaxNumberUsersInHtmlReport);
                    Add(" items - go to the advanced menu before running the report or add \"--no-enum-limit\" to remove that limit</td></tr></tfoot>");
                }
                Add(@"
			</table>
		</div>
	</div>
");

                GenerateSubSection("Advanced");
                AddParagraph("This section display advanced information, if any has been found");
                if (Report.lDAPIPDenyList != null && Report.lDAPIPDenyList.Count > 0)
                {
                    Add(@"
		<div class=""row"">
			<div class=""col-lg-12"">
				<p><strong>IP denied for LDAP communication</strong>
			</div>
		</div>");
                    AddBeginTable("LDAP forbidden list");
                    AddHeaderText("Entry");
                    AddBeginTableData();
                    foreach (var e in Report.lDAPIPDenyList)
                    {
                        AddBeginRow();
                        AddCellText(e);
                        AddEndRow();
                    }
                    AddEndTable();
                }
                if (Report.GPOHardenedPath != null && Report.GPOHardenedPath.Count > 0)
                {
                    AddAnchor("HardenedPaths");
                    Add(@"
		<div class=""row"">
			<div class=""col-lg-12"">
				<p><strong>Hardened Paths configuration</strong>
			</div>
		</div>");
                    AddBeginTable("Hardened Paths");
                    AddHeaderText("Policy Name");
                    AddHeaderText("Key");
                    AddHeaderText("RequireIntegrity");
                    AddHeaderText("RequireMutualAuthentication");
                    AddHeaderText("RequirePrivacy");

                    AddBeginTableData();
                    foreach (var e in Report.GPOHardenedPath)
                    {
                        AddBeginRow();
                        AddGPOName(e);
                        AddCellText(e.Key);
                        AddCellText(e.RequireIntegrity == null ? null : ((bool)e.RequireIntegrity ? "Required" : "Disabled"), e.RequireIntegrity == false, false);
                        AddCellText(e.RequireMutualAuthentication == null ? null : ((bool)e.RequireMutualAuthentication ? "Required" : "Disabled"), e.RequireMutualAuthentication == false, false);
                        AddCellText(e.RequirePrivacy == null ? null : ((bool)e.RequirePrivacy ? "Required" : "Disabled"), e.RequirePrivacy == false, false);
                        AddEndRow();
                    }
                    AddEndTable();
                }
            }
        }
        #endregion anomaly

        #region pki
        protected void GeneratePKIDetail()
        {
            // certificate
            GenerateSubSection("Certificates", "certificates");
            Add(@"
		<div class=""row"">
			<div class=""col-lg-12"">
				<p>This detects trusted certificates which can be used in man in the middle attacks, or which can issue smart card logon certificates</p>
				<p><strong>Number of trusted certificates:</strong> " + Report.TrustedCertificates.Count + @" 
			</div>
		</div>
		<div class=""row"">
			<div class=""col-lg-12"">
");
            GenerateAccordion("trustedCertificates", () =>
            {
                GenerateAccordionDetailForDetail("trustedCertificatesPanel", "trustedCertificates", "Trusted certificates", Report.TrustedCertificates.Count, () =>
                {
                    AddBeginTable("Certificates list");
                    AddHeaderText("Source");
                    AddHeaderText("Store");
                    AddHeaderText("Subject");
                    AddHeaderText("Issuer");
                    AddHeaderText("NotBefore");
                    AddHeaderText("NotAfter");
                    AddHeaderText("Module size");
                    AddHeaderText("Signature Alg");
                    AddHeaderText("SC Logon");
                    AddBeginTableData();

                    foreach (HealthcheckCertificateData data in Report.TrustedCertificates)
                    {
                        if (data.Certificate == null || data.Certificate.Length == 0)
                            continue;
                        X509Certificate2 cert = null;
                        try
                        {
                            cert = new X509Certificate2(data.Certificate);
                        }
                        catch (Exception)
                        {
                            continue;
                        }
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
                        AddBeginRow();
                        if (data.Source == "NTLMStore")
                        {
                            Add("<td class='text'>");
                            Add(@"Enterprise NTAuth");
                            AddBeginTooltip();
                            Add("This store is used by the Windows PKI. You can view it with the command 'certutil -viewstore -enterprise NTAuth' or edit it with the command 'Manage AD Container' of the 'Enterprise PKI' snapin of mmc.");
                            AddEndTooltip();
                            Add(@"</td>");
                        }
                        else
                        {
                            AddCellText(data.Source);
                        }
                        AddCellText(data.Store);
                        AddCellTextNoWrap(cert.Subject);
                        AddCellTextNoWrap(cert.Issuer);
                        AddCellDateNoWrap(cert.NotBefore);
                        AddCellDateNoWrap(cert.NotAfter);
                        AddCellNum(modulesize);
                        AddCellText(cert.SignatureAlgorithm.FriendlyName);
                        AddCellText(SCLogonAllowed.ToString());
                        AddEndRow();
                    }
                    AddEndTable();
                }
                );
            }
                );
            Add(@"
			</div>
		</div>
");

            if (Report.CertificateTemplates != null && Report.CertificateTemplates.Count > 0)
            {
                // certificate template
                GenerateSubSection("Certificate Templates", "certificatetemplates");
                Add(@"
		<div class=""row"">
			<div class=""col-lg-12"">
				<p>This section lists certificate templates which can be used to generate a certificate. A misconfiguration can allow an attacker to create its own certificate and use it to impersonate other users</p>
				<p><strong>Number of certificate templates:</strong> " + Report.CertificateTemplates.Count + @" 
			</div>
		</div>
		<div class=""row"">
			<div class=""col-lg-12"">
");
                GenerateAccordion("certificateTemplates", () =>
                {
                    GenerateAccordionDetailForDetail("certificateTemplatesPanel", "certificateTemplates", "Certificate Templates", Report.CertificateTemplates.Count, () =>
                    {
                        AddBeginTable("Certificate Templates list");
                        AddHeaderText("Name");
                        AddHeaderText("Destination");
                        AddHeaderText("Manager approval", "Require the CA certiicate manager approval before being issued");
                        AddHeaderText("Enrollee can supply subject", "Indicates if the user doing the request can submit its own subject or subject alternate name");
                        AddHeaderText("Issuance requirements", "Specify if an authorized signature is required before issuing the certificate");
                        AddHeaderText("Vulnerable ACL", "Specify if large group such as EVERYONE can take control of the template object");
                        AddHeaderText("Everyone can enroll", "Indicates if there is no security restriction to request a certificate");
                        AddHeaderText("Agent template", "Specify if the certificates issued by this template can generate certificates on behalf other users");
                        AddHeaderText("Any purpose", "Indicates if no restrictions are in place for the certificate use such as authentication or agent use");
                        AddHeaderText("For Authentication", "Indicates certificates issued will be used for authentication purpose");
                        AddHeaderText("Flag No Security", "Indicates if the object szOID_NTDS_CA_SECURITY_EXT will not be included");
                        AddBeginTableData();

                        foreach (var data in Report.CertificateTemplates)
                        {
                            AddBeginRow();
                            AddNameWithCA(data.Name, data.CA);
                            AddCellText((data.Flags & 0x40) > 0 ? "Computer" : "User");
                            AddCellText(data.CAManagerApproval ? "YES" : "NO", data.CAManagerApproval, true);
                            AddCellText(data.EnrolleeSupplies > 0 ? "YES" : "NO", data.EnrolleeSupplies > 0, false);
                            AddCellText(data.IssuanceRequirementsEmpty ? "NO" : "YES", !data.IssuanceRequirementsEmpty, true);
                            AddCellText(data.VulnerableTemplateACL ? "YES" : "NO", data.VulnerableTemplateACL, false);
                            AddCellText(data.LowPrivCanEnroll ? "YES" : "NO", data.LowPrivCanEnroll, false);
                            AddCellText(data.EnrollmentAgentTemplate ? "YES" : "NO", data.EnrollmentAgentTemplate, false);
                            AddCellText(data.HasAnyPurpose ? "YES" : "NO", data.HasAnyPurpose, false);
                            AddCellText(data.HasAuthenticationEku ? "YES" : "NO");
                            AddCellText(data.NoSecurityExtension ? "YES" : "NO", data.NoSecurityExtension);
                            AddEndRow();
                        }
                        AddEndTable();
                    }
                    );
                }
                    );
                Add(@"
			</div>
		</div>
");
                if (Report.version >= new Version(2, 10, 1))
                {
                    var ctdelegations = new List<HealthcheckDelegationData>();
                    foreach (var data in Report.CertificateTemplates)
                    {
                        if (data.Delegations != null)
                            ctdelegations.AddRange(data.Delegations);
                    }

                    Add(@"
		<div class=""row"">
			<div class=""col-lg-12"">");
                    AddParagraph("The delegations for certificate templates are listed below.");
                    GenerateAccordion("ctdelegationaccordeon",
                        () =>
                        {
                            GenerateAccordionDetailForDetail("ctalldelegation", "ctdelegationaccordeon", "Certificate Templates delegations", ctdelegations.Count, () => GenerateDelegationDetail(ctdelegations));
                        });
                    Add(@"
			</div>
		</div>
");
                }
            }

            int DCCertCount = 0;
            foreach (var dc in Report.DomainControllers)
            {
                if (dc.LDAPCertificate != null && dc.LDAPCertificate.Length > 0)
                    DCCertCount++;
            }
            if (DCCertCount > 0)
            {
                // certificate template
                GenerateSubSection("Domain Controller Certificate", "dccertificate");
                Add(@"
		<div class=""row"">
			<div class=""col-lg-12"">
				<p>This section lists certificates in use on Domain Controllers. They give an attacker hints about the PKI configuration.</p>
				<p><strong>Number of DC certificates:</strong> " + DCCertCount + @" 
			</div>
		</div>
		<div class=""row"">
			<div class=""col-lg-12"">
");
                GenerateAccordion("DCcertificates", () =>
                {
                    GenerateAccordionDetailForDetail("DCcertificatesPanel", "DCcertificates", "DC Certificates", DCCertCount, () =>
                    {
                        AddBeginTable("DC Certificates list");
                        AddHeaderText("DC Name");
                        AddHeaderText("Subject");
                        AddHeaderText("SAN", "Subject Alternate Name");
                        AddHeaderText("EKU", "Extended Key Usage");
                        AddHeaderText("Template", "The certificate template used to generate this certificate, if any");
                        AddHeaderText("NotBefore");
                        AddHeaderText("NotAfter");
                        AddHeaderText("Module size");
                        AddHeaderText("Signature Alg");
                        AddBeginTableData();

                        foreach (var dc in Report.DomainControllers)
                        {
                            if (dc.LDAPCertificate == null || dc.LDAPCertificate.Length == 0)
                                continue;
                            X509Certificate2 cert = null;
                            try
                            {
                                cert = new X509Certificate2(dc.LDAPCertificate);
                            }
                            catch (Exception)
                            {
                                continue;
                            }
                            string san = cert.GetNameInfo(X509NameType.DnsFromAlternativeName, false);
                            var intendedpurposes = string.Empty;
                            var templateName = string.Empty;
                            foreach (var ext in cert.Extensions)
                            {
                                var eku = ext as X509EnhancedKeyUsageExtension;
                                if (eku != null)
                                {
                                    foreach (var oid in eku.EnhancedKeyUsages)
                                    {
                                        intendedpurposes += oid.FriendlyName + ", ";
                                    }
                                }
                                // X509CertificateTemplateExtension not available in .net 2
                                else if (ext.Oid.Value == "1.3.6.1.4.1.311.21.7")
                                {
                                    AsnEncodedData asndata = new AsnEncodedData(ext.Oid, ext.RawData);
                                    var s = asndata.Format(false).Split(',');
                                    if (s.Length > 0 && !string.IsNullOrEmpty(s[0]) && s[0].Contains("="))
                                    {
                                        var TemplateOid = new Oid(s[0].Split('=')[1]);
                                        /*var MajorVersion = int.Parse(s[1].Split('=')[1]);
                                        var MinorVersion = int.Parse(s[2].Split('=')[1]);*/

                                        templateName = string.IsNullOrEmpty(TemplateOid.FriendlyName) ? TemplateOid.Value : TemplateOid.FriendlyName;
                                        if (Report.CertificateTemplates != null)
                                        {
                                            foreach (var template in Report.CertificateTemplates)
                                            {
                                                if (template.OID == TemplateOid.Value)
                                                {
                                                    templateName = template.Name;
                                                    break;
                                                }
                                            }
                                        }
                                    }
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
                            AddBeginRow();
                            AddCellText(dc.DCName);
                            AddCellText(cert.Subject);
                            AddCellText(san);
                            AddCellText(intendedpurposes);
                            AddCellText(templateName);
                            AddCellDateNoWrap(cert.NotBefore);
                            AddCellDateNoWrap(cert.NotAfter);
                            AddCellNum(modulesize);
                            AddCellText(cert.SignatureAlgorithm.FriendlyName);
                            AddEndRow();


                        }
                        AddEndTable();
                    }
                    );
                }
                    );
                Add(@"
			</div>
		</div>
");
            }
        }

        private void GenerateUnprotectedOUDetail(List<string> list)
        {
            AddBeginTable("Unprotected OU");
            AddHeaderText("DistinguishedName");
            AddBeginTableData();

            foreach (var item in list)
            {
                int dcPathPos = item.IndexOf(",DC=");
                string path = item;
                if (dcPathPos > 0)
                    path = item.Substring(0, dcPathPos);
                AddBeginRow();
                AddCellText(path);
                AddEndRow();
            }
            AddEndTable();
        }

        void AddNameWithCA(string Name, List<string> CA)
        {
            Add(@"<td class='text'>");
            AddEncoded(Name);
            if (CA != null && CA.Count > 0)
            {
                AddBeginTooltip(true, true);
                Add("<div class='text-start'>Used in:<br><ul>");
                foreach (var i in CA)
                {
                    Add("<li>");
                    AddEncoded(i);
                    Add("</li>");
                }
                Add("</ul></div>");
                AddEndTooltip();
            }
            Add("</td>");
        }

        #endregion pki

        #region password policies

        protected void GeneratePasswordPoliciesDetail()
        {
            GenerateSubSection("Password policies", "passwordpolicies");
            Add(@"<p>Note: PSO (Password Settings Objects) will be visible only if the user, which collected the information, has the permission to view it.<br>PSO shown in the report will be prefixed by &quot;PSO:&quot;</p>");
            AddBeginTable("Password policies list");
            AddHeaderText("Policy Name");
            AddHeaderText("Complexity");
            AddHeaderText("Max Password Age");
            AddHeaderText("Min Password Age");
            AddHeaderText("Min Password Length");
            AddHeaderText("Password History");
            AddHeaderText("Reversible Encryption");
            AddHeaderText("Lockout Threshold");
            AddHeaderText("Lockout Duration");
            AddHeaderText("Reset account counter locker after");
            AddBeginTableData();
            if (Report.GPPPasswordPolicy != null)
            {
                foreach (GPPSecurityPolicy policy in Report.GPPPasswordPolicy)
                {
                    AddBeginRow();
                    AddGPOName(policy);
                    AddPSOStringValue(policy, "PasswordComplexity");
                    AddPSOStringValue(policy, "MaximumPasswordAge");
                    AddPSOStringValue(policy, "MinimumPasswordAge");
                    AddPSOStringValue(policy, "MinimumPasswordLength");
                    AddPSOStringValue(policy, "PasswordHistorySize");
                    AddPSOStringValue(policy, "ClearTextPassword");
                    AddPSOStringValue(policy, "LockoutBadCount");
                    AddPSOStringValue(policy, "LockoutDuration");
                    AddPSOStringValue(policy, "ResetLockoutCount");
                    AddEndRow();
                }
            }
            AddEndTable();

            GenerateSubSection("Screensaver policies");
            AddParagraph("This is the settings related to screensavers stored in Group Policies. Each non compliant setting is written in red.");
            AddBeginTable("Screensaver policies list");
            AddHeaderText("Policy Name");
            AddHeaderText("Screensaver enforced");
            AddHeaderText("Password request");
            AddHeaderText("Start after (seconds)");
            AddHeaderText("Grace Period (seconds)");
            AddBeginTableData();
            if (Report.GPOScreenSaverPolicy != null)
            {
                foreach (GPPSecurityPolicy policy in Report.GPOScreenSaverPolicy)
                {
                    AddBeginRow();
                    AddGPOName(policy);
                    AddPSOStringValue(policy, "ScreenSaveActive");
                    AddPSOStringValue(policy, "ScreenSaverIsSecure");
                    AddPSOStringValue(policy, "ScreenSaveTimeOut");
                    AddPSOStringValue(policy, "ScreenSaverGracePeriod");
                    AddEndRow();
                }
            }
            AddEndTable();
        }

        #endregion password policies

        #region GPO
        protected void GenerateGPODetail()
        {
            AddParagraph("This section focuses on security settings stored in the Active Directory technical security policies.");
            GenerateSubSection("Obfuscated Passwords", "gpoobfuscatedpassword");
            AddParagraph("The password in GPO are obfuscated, not encrypted. Consider any passwords listed here as compromised and change them immediately.");
            if (Report.GPPPassword != null && Report.GPPPassword.Count > 0)
            {
                AddBeginTable("Obfuscated passwords list");
                AddHeaderText("GPO Name");
                AddHeaderText("Password origin");
                AddHeaderText("UserName");
                AddHeaderText("Password");
                AddHeaderText("Changed");
                AddHeaderText("Other");
                AddBeginTableData();
                foreach (GPPPassword password in Report.GPPPassword)
                {
                    AddBeginRow();
                    AddGPOName(password);
                    AddCellText(password.Type);
                    AddCellText(password.UserName);
                    AddCellText(password.Password, true);
                    AddCellDate(password.Changed);
                    AddCellText(password.Other);
                    AddEndRow();
                }
                AddEndTable();
            }

            GenerateSubSection("Restricted Groups");
            AddParagraph("Giving local group membership in a GPO is a way to become administrator.<br>The local admin of a domain controller can become domain administrator instantly.");
            if (Report.GPOLocalMembership != null && Report.GPOLocalMembership.Count > 0)
            {
                Report.GPOLocalMembership.Sort((GPOMembership a, GPOMembership b) =>
                {
                    int sort = String.Compare(a.GPOName, b.GPOName);
                    if (sort == 0)
                        sort = String.Compare(a.User, b.User);
                    if (sort == 0)
                        sort = String.Compare(a.MemberOf, b.MemberOf);
                    return sort;
                }
                );
                AddBeginTable("restricted groups list");
                AddHeaderText("GPO Name");
                AddHeaderText("User or group");
                AddHeaderText("Member of");
                AddBeginTableData();

                foreach (GPOMembership membership in Report.GPOLocalMembership)
                {
                    AddBeginRow();
                    AddCellText(membership.GPOName);
                    AddCellText(membership.User);
                    AddCellText(membership.MemberOf);
                    AddEndRow();
                }
                AddEndTable();
            }

            GenerateSubSection("Security settings", "lsasettings");
            AddParagraph(@"A GPO can be used to deploy security settings to workstations.<br>The best practice out of the default security baseline is reported in <span class=""ticked"">green</span>.<br>The following settings in <span class=""unticked"">red</span> are unsual and may need to be reviewed.<br>Each setting is accompanied with its value and a link to the GPO explanation.");
            AddParagraph("You will find below the checks where no occurences have been found");
            AddBeginTable("Security settings list");
            AddHeaderText("Policy Name");
            AddHeaderText("Setting");
            AddHeaderText("Value");
            AddBeginTableData();
            if (Report.GPOLsaPolicy != null)
            {
                foreach (GPPSecurityPolicy policy in Report.GPOLsaPolicy)
                {
                    foreach (GPPSecurityPolicyProperty property in policy.Properties)
                    {
                        AddBeginRow();
                        AddGPOName(policy);
                        Add(@"<td class='text'>");
                        Add(GetLinkForLsaSetting(property.Property));
                        Add(@"</td>");
                        AddLsaSettingsValue(property.Property, property.Value);
                        AddEndRow();
                    }
                }
            }
            AddEndTable();

            if (Report.version >= new Version(2, 8))
            {
                GenerateSubSection("Audit settings", "auditsettings");
                AddParagraph(@"Audit settings allow the system to generate logs which are useful to detect intrusions. Here are the settings found in GPO.");
                AddParagraph("Simple audit events are <a href='https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/01f8e057-f6a8-4d6e-8a00-99bcd241b403'>described here</a> and Advanced audit events are <a href='https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/77878370-0712-47cd-997d-b07053429f6d'>described here</a>");
                AddParagraph("You can get a list of all audit settings with the command line: <code>auditpol.exe /get /category:*</code> (<a href='https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/getting-the-effective-audit-policy-in-windows-7-and-2008-r2/ba-p/399010'>source</a>)");
                AddParagraph("Simple audit settings are located in: Computer Configuration / Policies / Windows Settings / Security Settings / Local Policies / Audit Policy. Simple audit settings are named [Simple Audit].");
                AddParagraph("Advanced audit settings are located in: Computer Configuration / Policies / Windows Settings / Security Settings / Advanced Audit Policy Configuration. This category is displayed below.");
                AddBeginTable("Audit settings list");
                AddHeaderText("Policy Name");
                AddHeaderText("Category");
                AddHeaderText("Setting");
                AddHeaderText("Value");
                AddBeginTableData();
                if (Report.GPOAuditSimple != null)
                {
                    foreach (var a in Report.GPOAuditSimple)
                    {
                        AddBeginRow();
                        AddGPOName(a);
                        AddCellText("[Simple Audit]");
                        AddCellText(GetAuditSimpleDescription(a.Category));
                        AddCellText(GetAuditSimpleValue(a.Value));
                        AddEndRow();
                    }
                }
                if (Report.GPOAuditSimple != null)
                {
                    foreach (var a in Report.GPOAuditAdvanced)
                    {
                        AddBeginRow();
                        AddGPOName(a);
                        AddCellText(GetAuditAdvancedCategory(a.SubCategory));
                        AddCellText(GetAuditAdvancedDescription(a.SubCategory));
                        AddCellText(GetAuditSimpleValue(a.Value));
                        AddEndRow();
                    }
                }
                AddEndTable();
            }

            GenerateSubSection("Privileges", "gpoprivileges");
            AddParagraph("Giving privileges in a GPO is a way to become administrator without being part of a group.<br>For example, SeTcbPriviledge gives the right to act as SYSTEM, which has more privileges than the administrator account.");
            if (Report.GPPRightAssignment != null && Report.GPPRightAssignment.Count > 0)
            {
                AddBeginTable("Privileges list");
                AddHeaderText("GPO Name");
                AddHeaderText("Privilege");
                AddHeaderText("Members");
                AddBeginTableData();

                foreach (GPPRightAssignment right in Report.GPPRightAssignment)
                {
                    AddBeginRow();
                    AddGPOName(right);
                    AddCellText(right.Privilege);
                    AddCellText(right.User);
                    AddEndRow();
                }
                AddEndTable();
            }

            if (Report.version >= new Version(2, 8))
            {
                GenerateSubSection("Login", "gpologin");
                AddParagraph("Login authorization and restriction can be set by GPOs. Indeed, by default, everyone is allowed to login on every computer except domain controllers. Defining login restriction is a way to have different isolated tiers. Here are the settings found in GPOs.");
                if (Report.GPPLoginAllowedOrDeny != null && Report.GPPLoginAllowedOrDeny.Count > 0)
                {
                    AddBeginTable("Login list");
                    AddHeaderText("GPO Name");
                    AddHeaderText("Privilege");
                    AddHeaderText("Members");
                    AddBeginTableData();

                    foreach (GPPRightAssignment right in Report.GPPLoginAllowedOrDeny)
                    {
                        AddBeginRow();
                        AddGPOName(right);
                        Add(@"<td class='text'>");
                        AddPrivilegeToGPO(right.Privilege);
                        Add(@"</td>");
                        AddCellText(right.User);
                        AddEndRow();
                    }
                    AddEndTable();
                }
            }

            GenerateSubSection("GPO Login script", "gpologin");
            AddParagraph("A GPO login script is a way to force the execution of data on behalf of users. Only enabled users are analyzed.");
            if (Report.GPOLoginScript != null && Report.GPOLoginScript.Count > 0)
            {
                AddBeginTable("GPO login script list");
                AddHeaderText("GPO Name");
                AddHeaderText("Action");
                AddHeaderText("Source");
                AddHeaderText("Command line");
                AddHeaderText("Parameters");
                AddBeginTableData();

                foreach (HealthcheckGPOLoginScriptData loginscript in Report.GPOLoginScript)
                {
                    AddBeginRow();
                    AddGPOName(loginscript);
                    AddCellText(loginscript.Action);
                    AddCellText(loginscript.Source);
                    AddCellText(loginscript.CommandLine);
                    AddCellText(loginscript.Parameters);
                    AddEndRow();
                }
                AddEndTable();
            }
            if (Report.version >= new Version(2, 7, 0, 0))
            {
                GenerateSubSection("GPO Deployed Files", "gpodeployedfiles");
                AddParagraph("A GPO can be used to deploy applications or copy files. These files may be controlled by a third party to control the execution of local programs.");
                if (Report.GPPFileDeployed != null && Report.GPPFileDeployed.Count > 0)
                {
                    AddBeginTable("GPO deployed files list");
                    AddHeaderText("GPO Name");
                    AddHeaderText("Type");
                    AddHeaderText("File");
                    AddBeginTableData();

                    foreach (var file in Report.GPPFileDeployed)
                    {
                        AddBeginRow();
                        AddGPOName(file);
                        AddCellText(file.Type);
                        AddCellText(file.FileName);
                        AddEndRow();
                    }
                    AddEndTable();
                }
            }

            if (Report.version > new Version(3, 2, 1, 0))
            {
                GenerateSubSection("Folder Options", "gpofolderoptions");
                AddParagraph("File associations may be managed through Group Policy Objects (GPO) by navigating to \"Folder Options\". This setting is located under Computer Configuration / Preferences / Control Panel Settings / Folders Options in the GPO.");
                AddParagraph("This method serves as an effective countermeasure against script execution from phishing emails by setting Notepad as the default program for opening script files, rather than the script engine. The script extensions that can be reconfigured include: .js, .jse, .vbs, .vbe, .vb, .wsh, and .wsf. Specifically, JavaScript files with extensions .js and .jse can be safely altered to open with Notepad. Other file extensions may have an impact and needs to be assessed before being configured.");
                if (Report.GPOFolderOptions != null)
                {
                    AddBeginTable("Folder Options");
                    AddHeaderText("GPO Name");
                    AddHeaderText("Type");
                    AddHeaderText("Action", "A for Add, R for Replace, U for update, D for delete");
                    AddHeaderText("Application");
                    AddBeginTableData();
                    foreach (var ext in Report.GPOFolderOptions)
                    {
                        AddBeginRow();
                        AddGPOName(ext);
                        AddCellText(ext.FileExt);
                        AddCellText(ext.Action);
                        AddCellText(ext.OpenApp);
                        AddEndRow();
                    }
                    AddEndTable();
                }
            }

            if (Report.version > new Version(3, 2, 1, 0))
            {
                GenerateSubSection("Microsoft Defender ASR (attack surface reduction)", "gpodefenderASR");
                AddParagraph("Microsoft Defender is the default Antivirus shipped with Windows. There are many alternatives, but if a computer is installed without an antivirus, it will be enabled by default.");
                AddParagraph("A set of mitigation named ASR (attack surface reduction) can be enabled, even on non premium version of Windows Defender. Some protections are available since Windows 10 1710 and even Windows 2012 R2. See https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide for more information.");
                AddParagraph("To enable a mitigation, enable the GPO \"Configure Attack Surface Redurction rules\" in Computer Configuration / Policies / Administrative Templates / Windows Components / Windows Defender Antivirus / Windows Defender Exploit Guard / Attack Surface Reduction. After having Enabled the setting, click on Set the state for each ASR rule. Add the GUID of the mitigation as Value name and set 1 as Value to enforce the Block mode. Example for Block JavaScript or VBScript from launching downloaded executable content: d3e037e1-3eb8-44c8-a917-57927947596d. The other values are: 2 for Audit and 6 for Warn.");
                if (Report.GPODefenderASR != null)
                {
                    AddBeginTable("Defender ASR");
                    AddHeaderText("GPO Name");
                    AddHeaderText("Rule");
                    AddHeaderText("Description");
                    AddHeaderText("Action");
                    AddBeginTableData();
                    foreach (var asr in Report.GPODefenderASR)
                    {
                        AddBeginRow();
                        AddGPOName(asr);
                        AddCellText(asr.ASRRule);
                        Add(@"<td class='text'>");
                        Add(GetDefenderASRLabelLink(asr.ASRRule));
                        Add("</td>");
                        switch (asr.Action)
                        {
                            case 0:
                                AddCellText("Not configured");
                                break;
                            case 1:
                                AddCellText("Block");
                                break;
                            case 2:
                                AddCellText("Audit");
                                break;
                            case 6:
                                AddCellText("Warn");
                                break;
                            default:
                                AddCellText(asr.Action.ToString());
                                break;
                        }
                        AddEndRow();
                    }
                    AddEndTable();
                }
            }

            if (Report.version > new Version(3, 2, 1, 0))
            {
                GenerateSubSection("Firewall configuration", "gpofirewall");
                AddParagraph("Firewall rules may be managed through Group Policy Objects (GPO). This setting is located under Computer Configuration / Policies Windows Settings / Security Settings / Windows Defender Firewall with Advanced Security.");
                if (Report.GPPFirewallRules != null)
                {
                    AddBeginTable("Firewall Rules");
                    AddHeaderText("GPO Name");
                    AddHeaderText("Name");
                    AddHeaderText("Active");
                    AddHeaderText("Direction");
                    AddHeaderText("Action");
                    AddHeaderText("Application");
                    AddHeaderText("Remote IP");
                    AddBeginTableData();
                    foreach (var fw in Report.GPPFirewallRules)
                    {
                        AddBeginRow();
                        AddGPOName(fw);
                        AddCellText(fw.Name);
                        AddCellBool(fw.Active);
                        AddCellText(fw.Direction);
                        AddCellText(fw.Action);
                        AddCellText(fw.App);
                        string ip = null;
                        if (fw.RA4 != null)
                        {
                            ip += string.Join(",", fw.RA4);
                        }
                        if (fw.RA6 != null)
                        {
                            if (!string.IsNullOrEmpty(ip))
                                ip += ",";
                            ip += string.Join(",", fw.RA6);
                        }
                        AddCellText(ip);
                        AddEndRow();
                    }
                    AddEndTable();
                }
            }
        }

        private string GetDefenderASRLabelLink(string rule)
        {
            var label = GetDefenderASRLabel(rule);
            var url = "https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide#" + label.Replace(" ", "-").Replace("(", "").Replace(")", "").ToLowerInvariant();
            return "<a href=\"" + url + "\">" + label + "</a>";
        }

        private string GetDefenderASRLabel(string rule)
        {
            switch (rule.ToLowerInvariant())
            {
                case "56a863a9-875e-4185-98a7-b882c64b5ce5": return "Block abuse of exploited vulnerable signed drivers";
                case "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c": return "Block Adobe Reader from creating child processes";
                case "d4f940ab-401b-4efc-aadc-ad5f3c50688a": return "Block all Office applications from creating child processes";
                case "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2": return "Block credential stealing from the Windows local security authority subsystem (lsass.exe)";
                case "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550": return "Block executable content from email client and webmail";
                case "01443614-cd74-433a-b99e-2ecdc07bfc25": return "Block executable files from running unless they meet a prevalence, age, or trusted list criterion";
                case "5beb7efe-fd9a-4556-801d-275e5ffc04cc": return "Block execution of potentially obfuscated scripts";
                case "d3e037e1-3eb8-44c8-a917-57927947596d": return "Block JavaScript or VBScript from launching downloaded executable content";
                case "3b576869-a4ec-4529-8536-b80a7769e899": return "Block Office applications from creating executable content";
                case "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84": return "Block Office applications from injecting code into other processes";
                case "26190899-1602-49e8-8b27-eb1d0a1ce869": return "Block Office communication application from creating child processes";
                case "e6db77e5-3df2-4cf1-b95a-636979351e5b": return "Block persistence through WMI event subscription";
                case "d1e49aac-8f56-4280-b9ba-993a6d77406c": return "Block process creations originating from PSExec and WMI commands";
                case "33ddedf1-c6e0-47cb-833e-de6133960387": return "Block rebooting machine in Safe Mode (preview)";
                case "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4": return "Block untrusted and unsigned processes that run from USB";
                case "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb": return "Block use of copied or impersonated system tools (preview)";
                case "a8f5898e-1dc8-49a9-9878-85004b8a61e6": return "Block Webshell creation for Servers";
                case "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b": return "Block Win32 API calls from Office macros";
                case "c1db55ab-c21a-4637-bb3f-a12568109d35": return "Use advanced protection against ransomware";
                default:
                    return "";
            }
        }

        private string GetAUOptionsText(HealthcheckWSUSData data, string name)
        {
            HealthcheckWSUSDataOption Option = null;
            foreach (var o in data.Options)
            {
                if (o.Name == name)
                {
                    Option = o;
                    break;
                }
            }
            if (Option == null)
            {
                if (name == "UseWUServer")
                    return "The WUServer value is not respected unless this key is set";
                return null;

            }
            if (Option.Name == "AUOptions")
            {
                switch (Option.Value)
                {
                    case 2:
                        return "Notify before download";
                    case 3:
                        return "Automatically download and notify of installation";
                    case 4:
                        return "Automatic download and scheduled installation";
                    case 5:
                        return "Automatic Updates is required, but end users can configure it";
                }
            }
            else if (Option.Name == "NoAutoUpdate")
            {
                switch (Option.Value)
                {
                    case 0:
                        return "Enable Automatic Updates";
                    case 1:
                        return "Disable Automatic Updates";
                }
            }
            else if (Option.Name == "UseWUServer")
            {
                return "UseWUServer set";
            }
            else if (Option.Name == "NoAutoRebootWithLoggedOnUsers")
            {
                switch (Option.Value)
                {
                    case 0:
                        return "Automatic Updates notifies user that the computer will restart in 5 minutes";
                    case 1:
                        return "Logged-on user gets to choose whether or not to restart his or her computer";
                }
            }
            else if (Option.Name == "ElevateNonAdmins")
            {
                switch (Option.Value)
                {
                    case 0:
                        return "Only users in the Administrators user group can approve or disapprove updates";
                    case 1:
                        return "Users in the Users security group are allowed to approve or disapprove updates";
                }
            }
            return "Unknown option (" + Option.Value + ")";
        }

        private string GetAuditSimpleDescription(string category)
        {
            switch (category)
            {
                case "AuditSystemEvents":
                    return "Audit system events";
                case "AuditLogonEvents":
                    return "Audit logon events";
                case "AuditPrivilegeUse":
                    return "Audit privilege use";
                case "AuditPolicyChange":
                    return "Audit policy change";
                case "AuditAccountManage":
                    return "Audit account management";
                case "AuditProcessTracking":
                    return "Audit process tracking";
                case "AuditDSAccess":
                    return "Audit directory service access";
                case "AuditObjectAccess":
                    return "Audit object access";
                case "AuditAccountLogon":
                    return "Audit account logon events";
                default:
                    return category;
            }

        }

        private class AuditAdvancedDescription
        {
            public string target { get; set; }
            public string subcategory { get; set; }
            public AuditAdvancedDescription(string t, string s)
            {
                target = t;
                subcategory = s;
            }
        }
        static Dictionary<Guid, AuditAdvancedDescription> auditAdvancedDescription = new Dictionary<Guid, AuditAdvancedDescription>
        {
            {new Guid("{0CCE9213-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("System", "IPsec Driver")},
            {new Guid("{0CCE9212-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("System", "System Integrity")},
            {new Guid("{0CCE9211-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("System", "Security System Extension")},
            {new Guid("{0CCE9210-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("System", "Security State Change")},
            {new Guid("{0CCE9214-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("System", "Other System Events")},
            {new Guid("{0CCE9243-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("Logon/Logoff", "Network Policy Server")},
            {new Guid("{0CCE921C-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("Logon/Logoff", "Other Logon/Logoff")},
            {new Guid("{0CCE921B-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("Logon/Logoff", "Special Logon")},
            {new Guid("{0CCE921A-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("Logon/Logoff", "IPsec Extended Mode")},
            {new Guid("{0CCE9219-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("Logon/Logoff", "IPsec Quick Mode")},
            {new Guid("{0CCE9218-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("Logon/Logoff", "IPsec Main Mode")},
            {new Guid("{0CCE9217-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("Logon/Logoff", "Account Lockout")},
            {new Guid("{0CCE9216-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("Logon/Logoff", "Logoff")},
            {new Guid("{0CCE9215-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("Logon/Logoff", "Logon")},
            {new Guid("{0CCE9223-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("Object Access", "Handle Manipulation")},
            {new Guid("{0CCE9244-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("Object Access", "Detailed File Share")},
            {new Guid("{0CCE9227-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("Object Access", "Other Object Access")},
            {new Guid("{0CCE9226-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("Object Access", "Filtering Platform Connection")},
            {new Guid("{0CCE9225-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("Object Access", "Filtering Platform Packet Drop")},
            {new Guid("{0CCE9224-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("Object Access", "File Share")},
            {new Guid("{0CCE9222-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("Object Access", "Application Generated")},
            {new Guid("{0CCE9221-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("Object Access", "Certification Services")},
            {new Guid("{0CCE9220-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("Object Access", "SAM")},
            {new Guid("{0CCE921F-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("Object Access", "Kernel Object")},
            {new Guid("{0CCE921E-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("Object Access", "Registry")},
            {new Guid("{0CCE921D-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("Object Access", "File System")},
            {new Guid("{0CCE9229-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("Privilege Use", "Non Sensitive Privilege Use")},
            {new Guid("{0CCE922A-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("Privilege Use", "Other Privilege Use Events")},
            {new Guid("{0CCE9228-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("Privilege Use", "Sensitive Privilege Use")},
            {new Guid("{0CCE922D-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("Detailed Tracking", "DPAPI Activity")},
            {new Guid("{0CCE922C-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("Detailed Tracking", "Process Termination")},
            {new Guid("{0CCE922B-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("Detailed Tracking", "Process Creation")},
            {new Guid("{0CCE922E-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("Detailed Tracking", "RPC Events")},
            {new Guid("{0CCE9232-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("Policy Change", "MPSSVC Rule-Level Policy Change")},
            {new Guid("{0CCE9234-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("Policy Change", "Other Policy Change Events")},
            {new Guid("{0CCE9233-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("Policy Change", "Filtering Platform Policy Change")},
            {new Guid("{0CCE922F-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("Policy Change", "Audit Policy Change")},
            {new Guid("{0CCE9231-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("Policy Change", "Authorization Policy Change")},
            {new Guid("{0CCE9230-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("Policy Change", "Authentication Policy Change")},
            {new Guid("{0CCE923A-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("Account Management", "Other Account Management Events")},
            {new Guid("{0CCE9239-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("Account Management", "Application Group Management")},
            {new Guid("{0CCE9238-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("Account Management", "Distribution Group Management")},
            {new Guid("{0CCE9237-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("Account Management", "Security Group Management")},
            {new Guid("{0CCE9236-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("Account Management", "Computer Account Management")},
            {new Guid("{0CCE9235-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("Account Management", "User Account Management")},
            {new Guid("{0CCE923E-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("DS Access", "Detailed Directory Service Replication")},
            {new Guid("{0CCE923B-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("DS Access", "Directory Service Access")},
            {new Guid("{0CCE923D-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("DS Access", "Directory Service Replication")},
            {new Guid("{0CCE923C-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("DS Access", "Directory Service Changes")},
            {new Guid("{0CCE9241-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("Account Logon", "Other Account Logon Events")},
            {new Guid("{0CCE9240-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("Account Logon", "Kerberos Service Ticket Operations")},
            {new Guid("{0CCE923F-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("Account Logon", "Credential Validation")},
            {new Guid("{0CCE9242-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("Account Logon", "Kerberos Authentication Service")},
            {new Guid("{0CCE9245-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("System", "Removable Storage")},
            {new Guid("{0CCE9246-69AE-11D9-BED3-505054503030}"), new AuditAdvancedDescription("System", "Central Access Policy Staging")},
            {new Guid("{0cce9247-69ae-11d9-bed3-505054503030}"), new AuditAdvancedDescription("System", "User/Device Claims")},
            {new Guid("{0cce9248-69ae-11d9-bed3-505054503030}"), new AuditAdvancedDescription("System", "PNP Activity")},
            {new Guid("{0cce9249-69ae-11d9-bed3-505054503030}"), new AuditAdvancedDescription("System", "Group Membership")},

        };

        private string GetAuditAdvancedCategory(Guid guid)
        {
            if (auditAdvancedDescription.ContainsKey(guid))
            {
                return auditAdvancedDescription[guid].target;
            }
            else
            {
                return "Undocumented";
            }
        }

        private string GetAuditAdvancedDescription(Guid guid)
        {
            if (auditAdvancedDescription.ContainsKey(guid))
            {
                return auditAdvancedDescription[guid].subcategory;
            }
            else
            {
                return "Undocumented (" + guid + ")";
            }
        }

        private string GetAuditSimpleValue(int value)
        {
            switch (value)
            {
                case 0: return "Unchanged";
                default:
                    return "No Auditing";
                case 1:
                    return "Success";
                case 2:
                    return "Failure";
                case 3:
                    return "Success and Failure";
            }
        }

        private string GetAuditUserValue(int value)
        {
            if (value == 1)
                return "Success";
            if (value == 4)
                return "Failure";
            if (value == 5)
                return "Success and Failure";
            if (value == 0)
                return "None";
            var match = new List<string>();
            if ((value & 1) != 0)
            {
                match.Add("Success");
            }
            if ((value & 2) != 0)
            {
                match.Add("Exclude Success");
            }
            if ((value & 4) != 0)
            {
                match.Add("Failure");
            }
            if ((value & 8) != 0)
            {
                match.Add("Exclude Failure");
            }
            return string.Join(" and ", match.ToArray());
        }

        private void AddPrivilegeToGPO(string privilege)
        {
            string gpodescr = null;
            if (string.Equals(privilege, "SeInteractiveLogonRight", StringComparison.OrdinalIgnoreCase))
            {
                gpodescr = "Allow log on locally";
            }
            else if (string.Equals(privilege, "SeRemoteInteractiveLogonRight", StringComparison.OrdinalIgnoreCase))
            {
                gpodescr = "Allow logon through Remote Desktop Services";
            }
            else if (string.Equals(privilege, "SeNetworkLogonRight", StringComparison.OrdinalIgnoreCase))
            {
                gpodescr = "Access this computer from the network";
            }
            else if (string.Equals(privilege, "SeServiceLogonRight", StringComparison.OrdinalIgnoreCase))
            {
                gpodescr = "Log on as a service";
            }
            else if (string.Equals(privilege, "SeBatchLogonRight", StringComparison.OrdinalIgnoreCase))
            {
                gpodescr = "Log on as a batch job";
            }
            else if (string.Equals(privilege, "SeDenyServiceLogonRight", StringComparison.OrdinalIgnoreCase))
            {
                gpodescr = "Deny log on as a service";
            }
            else if (string.Equals(privilege, "SeDenyRemoteInteractiveLogonRight", StringComparison.OrdinalIgnoreCase))
            {
                gpodescr = "Deny logon through Remote Desktop Services";
            }
            else if (string.Equals(privilege, "SeDenyNetworkLogonRight", StringComparison.OrdinalIgnoreCase))
            {
                gpodescr = "Deny access to this computer from the network";
            }
            else if (string.Equals(privilege, "SeDenyInteractiveLogonRight", StringComparison.OrdinalIgnoreCase))
            {
                gpodescr = "Deny log on locally";
            }
            else if (string.Equals(privilege, "SeDenyBatchLogonRight", StringComparison.OrdinalIgnoreCase))
            {
                gpodescr = "Deny log on as a batch job";
            }
            else if (string.Equals(privilege, "SeDebugPrivilege", StringComparison.OrdinalIgnoreCase))
            {
                gpodescr = "Debug programs";
            }
            else if (string.Equals(privilege, "SeBackupPrivilege", StringComparison.OrdinalIgnoreCase))
            {
                gpodescr = "Back up files and directories";
            }
            else if (string.Equals(privilege, "SeCreateTokenPrivilege", StringComparison.OrdinalIgnoreCase))
            {
                gpodescr = "Create a token object";
            }
            else if (string.Equals(privilege, "SeEnableDelegationPrivilege", StringComparison.OrdinalIgnoreCase))
            {
                gpodescr = "Enable computer and user accounts to be trusted for delegation";
            }
            else if (string.Equals(privilege, "SeSyncAgentPrivilege", StringComparison.OrdinalIgnoreCase))
            {
                gpodescr = "Synchronize directory service data";
            }
            else if (string.Equals(privilege, "SeTakeOwnershipPrivilege", StringComparison.OrdinalIgnoreCase))
            {
                gpodescr = "Take ownership of files or other objects";
            }
            else if (string.Equals(privilege, "SeTcbPrivilege", StringComparison.OrdinalIgnoreCase))
            {
                gpodescr = "Act as part of the operating system";
            }
            else if (string.Equals(privilege, "SeTrustedCredManAccessPrivilege", StringComparison.OrdinalIgnoreCase))
            {
                gpodescr = "Access Credential Manager as a trusted caller";
            }
            else if (string.Equals(privilege, "SeMachineAccountPrivilege", StringComparison.OrdinalIgnoreCase))
            {
                gpodescr = "Add workstations to domain";
            }
            else if (string.Equals(privilege, "SeLoadDriverPrivilege", StringComparison.OrdinalIgnoreCase))
            {
                gpodescr = "Load and unload device drivers";
            }
            else if (string.Equals(privilege, "SeRestorePrivilege", StringComparison.OrdinalIgnoreCase))
            {
                gpodescr = "Restore files and directories";
            }
            else if (string.Equals(privilege, "SeImpersonatePrivilege", StringComparison.OrdinalIgnoreCase))
            {
                gpodescr = "Impersonate a client after authentication";
            }
            else if (string.Equals(privilege, "SeAssignPrimaryTokenPrivilege", StringComparison.OrdinalIgnoreCase))
            {
                gpodescr = "Replace a process level token";
            }
            if (gpodescr == null)
            {
                AddEncoded(privilege);
            }
            else
            {
                Add(gpodescr);
                AddBeginTooltip();
                AddEncoded(privilege);
                AddEndTooltip();
            }

        }
        #endregion GPO
    }
}
