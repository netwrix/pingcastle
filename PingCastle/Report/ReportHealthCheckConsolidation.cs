//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Data;
using PingCastle.Healthcheck;
using PingCastle.Rules;
using PingCastle.template;
using System;
using System.Collections.Generic;
using System.Reflection;
using System.Text;
using System.Linq;

namespace PingCastle.Report
{
    public class ReportHealthCheckConsolidation : ReportRiskControls<HealthcheckData>
    {
        private PingCastleReportCollection<HealthcheckData> Report;
        public ReportHealthCheckConsolidation(ADHealthCheckingLicense license) : base(license) { }
        public string GenerateReportFile(PingCastleReportCollection<HealthcheckData> report, ADHealthCheckingLicense license, string filename)
        {
            Report = report;
            _license = license;
            Brand(license);
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
        }

        protected override void GenerateTitleInformation()
        {
            Add("PingCastle Consolidation report - ");
            Add(DateTime.Now.ToString("yyyy-MM-dd"));
        }

        protected override void ReferenceJSAndCSS()
        {
            AddStyle(TemplateManager.LoadReportHealthCheckConsolidationCss());
            if (!_license.IsBasic())
            {
                AddScript(TemplateManager.LoadTableExportJs());
                AddScript(TemplateManager.LoadBootstrapTableExportJs());
            }
        }

        protected override void Hook(StringBuilder sbHtml)
        {
            sbHtml.Replace("<body>", @"<body data-spy=""scroll"" data-bs-target="".navbar"" data-offset=""50"">");
        }

        protected override void GenerateBodyInformation()
        {
            Version version = Assembly.GetExecutingAssembly().GetName().Version;
            string versionString = version.ToString(4);
#if DEBUG
            versionString += " Beta";
#endif
            GenerateNavigation("Consolidation", null);
            GenerateAbout();
            Add($@"
<div id=""wrapper"" class=""container-fluid well"">
	<noscript>
		<div class=""alert alert-warning"">
			<p>PingCastle reports work best with Javascript enabled.</p>
		</div>
	</noscript>
    <div class=""row"">
        <div class=""col-lg-12"">
            <div class=""d-flex justify-content-between align-items-center report-header"">
                <h1>Consolidation</h1>
                <h3 class=""report-date"">Date: {DateTime.Now.ToString("yyyy-MM-dd")} - Engine version: {versionString} </h3></div>
        </div>
    </div>
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
		<ul class=""nav nav-tabs nav-fill fs-4"" role=""tablist"">");
            GenerateTabHeader("Active Directory Indicators", selectedTab, true);
            GenerateTabHeader("Rules Matched", selectedTab);
            GenerateTabHeader("Domain Information", selectedTab);
            GenerateTabHeader("User Information", selectedTab);
            GenerateTabHeader("Computer Information", selectedTab);
            GenerateTabHeader("DC Information", selectedTab);
            GenerateTabHeader("Admin Groups", selectedTab);
            GenerateTabHeader("Control Paths", selectedTab);
            GenerateTabHeader("Trusts", selectedTab);
            GenerateTabHeader("Anomalies", selectedTab);
            GenerateTabHeader("Password", selectedTab);
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
            GenerateSectionFluid("DC Information", GenerateDCInformation, selectedTab);
            GenerateSectionFluid("Admin Groups", GenerateAdminGroupsInformation, selectedTab);
            GenerateSectionFluid("Control Paths", GenerateControlPathsInformation, selectedTab);
            GenerateSectionFluid("Trusts", GenerateTrustInformation, selectedTab);
            GenerateSectionFluid("Anomalies", GenerateAnomalyDetail, selectedTab);
            GenerateSectionFluid("Password", GeneratePasswordPoliciesDetail, selectedTab);
            GenerateSectionFluid("GPO", GenerateGPODetail, selectedTab);

            Add(@"
		</div>
	</div>
</div>");
        }

        public IActionPlanConsolidation ActionPlanOrchestratorConsolidation { get; set; }

        private void GenerateRulesMatched()
        {
            GenerateSection("Rules that matched", () =>
            {
                AddBeginTable("Rules consolidation");
                AddHeaderText("Domain");
                if (AdditionInfoDelegate != null)
                    AddHeaderText("Domain Info");
                AddHeaderText("Category");
                AddHeaderText("Rule");
                AddHeaderText("Score");
                AddHeaderText("Description");
                AddHeaderText("Rationale");
                if (ActionPlanOrchestratorConsolidation != null)
                {
                    AddHeaderText("Action plan");
                }
                AddBeginTableData();
                foreach (HealthcheckData data in Report)
                {
                    if (ActionPlanOrchestratorConsolidation != null)
                        ActionPlanOrchestratorConsolidation.LoadDomain(data);
                    foreach (HealthcheckRiskRule rule in data.RiskRules)
                    {
                        AddBeginRow();
                        AddPrintDomain(data.Domain, risk: rule.RiskId);
                        if (AdditionInfoDelegate != null)
                            AddCellText(AdditionInfoDelegate(data.Domain));
                        AddCellText(ReportHelper.GetEnumDescription(rule.Category));
                        if (_license.IsBasic())
                        {
                            AddCellText(rule.RiskId);
                        }
                        else
                        {
                            var hcrule = RuleSet<HealthcheckData>.GetRuleFromID(rule.RiskId);
                            Add("<td class='text'>");
                            if (hcrule != null)
                            {
                                Add("<span class='badge grade-");
                                Add(hcrule.MaturityLevel);
                                Add("'>");
                                Add(hcrule.MaturityLevel);
                                Add("</span> ");
                            }
                            AddEncoded(rule.RiskId);
                            Add("</td>");
                        }
                        AddCellNum(rule.Points);
                        AddCellText(RuleSet<HealthcheckData>.GetRuleDescription(rule.RiskId));
                        AddCellText(rule.Rationale);
                        if (ActionPlanOrchestratorConsolidation != null)
                        {
                            Add("<td>");
                            var hcrule = RuleSet<HealthcheckData>.GetRuleFromID(rule.RiskId);
                            if (hcrule != null)
                            {
                                ActionPlanOrchestratorConsolidation.GenerateMainActionPlan(sb, rule, hcrule);
                            }
                            Add("</td>");
                        }
                        AddEndRow();
                    }
                }
                AddEndTable();
            });
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
            GenerateSection("Indicators", () =>
            {
                Add(@"
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
            });
            GenerateIndicatorsTable();
        }

        private void GenerateIndicatorsTable()
        {
            GenerateSection("Score detail", () =>
            {

                AddBeginTable("Indicators list");
                AddHeaderText("Domain");
                if (AdditionInfoDelegate != null)
                    AddHeaderText("Domain Info");
                AddHeaderText("Domain Risk Level");
                AddHeaderText("Maturity Level");
                AddHeaderText("Stale objects");
                AddHeaderText("Privileged accounts");
                AddHeaderText("Trusts");
                AddHeaderText("Anomalies");
                AddHeaderText("Generated");
                AddBeginTableData();
                foreach (HealthcheckData data in Report)
                {
                    AddBeginRow();
                    AddPrintDomain(data.Domain);
                    if (AdditionInfoDelegate != null)
                        AddCellText(AdditionInfoDelegate(data.Domain));
                    AddCellNumScore(data.GlobalScore);
                    Add("<td class='num'>");
                    Add("<span class='badge grade-");
                    Add(data.MaturityLevel);
                    Add("'>");
                    Add(data.MaturityLevel);
                    Add("</span>");
                    Add("</td>");
                    AddCellNumScore(data.StaleObjectsScore);
                    AddCellNumScore(data.PrivilegiedGroupScore);
                    AddCellNumScore(data.TrustScore);
                    AddCellNumScore(data.AnomalyScore);
                    AddCellDate(data.GenerationDate);
                    AddEndRow();
                }
                AddEndTable();
            });
        }
        #endregion indicators

        #region domain information
        private void GenerateDomainInformation()
        {
            GenerateSection("List of domains", () =>
            {
                AddBeginTable("Domain information");
                AddHeaderText("Domain");
                if (AdditionInfoDelegate != null)
                    AddHeaderText("Domain Info");
                AddHeaderText("Netbios Name");
                AddHeaderText("Domain Functional Level");
                AddHeaderText("Forest Functional Level");
                AddHeaderText("Creation date");
                AddHeaderText("Nb DC");
                AddHeaderText("Engine");
                AddHeaderText("Level");
                AddHeaderText("Schema version");
                AddBeginTableData();

                foreach (HealthcheckData data in Report)
                {
                    AddBeginRow();
                    AddPrintDomain(data.Domain);
                    if (AdditionInfoDelegate != null)
                        AddCellText(AdditionInfoDelegate(data.Domain));
                    AddCellText(data.NetBIOSName);
                    AddCellText(ReportHelper.DecodeDomainFunctionalLevel(data.DomainFunctionalLevel));
                    AddCellText(ReportHelper.DecodeForestFunctionalLevel(data.ForestFunctionalLevel));
                    AddCellDate(data.DomainCreation);
                    AddCellNum(data.NumberOfDC);
                    AddCellText(data.EngineVersion);
                    AddCellText(data.Level.ToString());
                    AddCellText(ReportHelper.GetSchemaVersion(data.SchemaVersion));
                    AddEndRow();
                }
                AddEndTable(() =>
                {
                    AddCellText("Total");
                    AddCellNum(Report.Count);
                    AddCellText(null);
                    AddCellText(null);
                    AddCellText(null);
                    AddCellText(null);
                    AddCellText(null);
                    AddCellText(null);
                    AddCellText(null);
                });
            });
            GenerateSection("List of domain controllers", () =>
            {
                AddBeginTable("List of Domain Controllers");
                AddHeaderText("Source");
                AddHeaderText("Name");
                AddHeaderText("OS");
                AddHeaderText("Creation");
                AddHeaderText("Startup time");
                AddHeaderText("IP");
                AddHeaderText("FSMO");
                AddBeginTableData();
                foreach (HealthcheckData data in Report)
                {
                    foreach (var dc in data.DomainControllers)
                    {
                        AddBeginRow();
                        AddPrintDomain(data.Domain);
                        AddCellText(dc.DCName);
                        AddCellText(dc.OperatingSystem);
                        AddCellDate(dc.CreationDate);
                        AddCellDate(dc.StartupTime);
                        AddCellText(dc.IP == null ? string.Empty : string.Join(",", dc.IP.ToArray()));
                        AddCellText(dc.FSMO == null ? string.Empty : string.Join(",", dc.FSMO.ToArray()));
                        AddEndRow();
                    }
                }
                AddEndTable();
            });

        }
        #endregion domain information

        #region user
        private void GenerateUserInformation()
        {
            GenerateSection("Analysis of users", () =>
            {
                AddBeginTable("All users stats");
                AddHeaderText("Domain");
                AddHeaderText("Nb User Accounts");
                AddHeaderText("Nb Enabled");
                AddHeaderText("Nb Disabled");
                AddHeaderText("Nb Active");
                AddHeaderText("Nb Inactive");
                AddHeaderText("Nb Locked");
                AddHeaderText("Nb pwd never Expire");
                AddHeaderText("Nb SidHistory");
                AddHeaderText("Nb Bad PrimaryGroup");
                AddHeaderText("Nb Password not Req.");
                AddHeaderText("Nb Des enabled.");
                AddHeaderText("Nb Trusted delegation");
                AddHeaderText("Nb Reversible password");
                AddBeginTableData();
                HealthcheckAccountData total = new HealthcheckAccountData();
                foreach (HealthcheckData data in Report)
                {
                    if (data.UserAccountData == null)
                        continue;
                    total.Add(data.UserAccountData);
                    AddEndRow();
                    AddPrintDomain(data.Domain);
                    AddCellNum(data.UserAccountData.Number);
                    AddCellNum(data.UserAccountData.NumberEnabled);
                    AddCellNum(data.UserAccountData.NumberDisabled);
                    AddCellNum(data.UserAccountData.NumberActive);
                    AddCellNum(data.UserAccountData.NumberInactive);
                    AddCellNum(data.UserAccountData.NumberLocked);
                    AddCellNum(data.UserAccountData.NumberPwdNeverExpires);
                    AddCellNum(data.UserAccountData.NumberSidHistory);
                    AddCellNum(data.UserAccountData.NumberBadPrimaryGroup);
                    AddCellNum(data.UserAccountData.NumberPwdNotRequired);
                    AddCellNum(data.UserAccountData.NumberDesEnabled);
                    AddCellNum(data.UserAccountData.NumberTrustedToAuthenticateForDelegation);
                    AddCellNum(data.UserAccountData.NumberReversibleEncryption);
                    AddEndRow();
                }
                AddEndTable(() =>
                {
                    AddCellText("Total");
                    AddCellNum(total.Number);
                    AddCellNum(total.NumberEnabled);
                    AddCellNum(total.NumberDisabled);
                    AddCellNum(total.NumberActive);
                    AddCellNum(total.NumberInactive);
                    AddCellNum(total.NumberLocked);
                    AddCellNum(total.NumberPwdNeverExpires);
                    AddCellNum(total.NumberSidHistory);
                    AddCellNum(total.NumberBadPrimaryGroup);
                    AddCellNum(total.NumberPwdNotRequired);
                    AddCellNum(total.NumberDesEnabled);
                    AddCellNum(total.NumberTrustedToAuthenticateForDelegation);
                    AddCellNum(total.NumberReversibleEncryption);
                });
            });
        }
        #endregion user

        #region computer
        private void GenerateComputerInformation()
        {
            GenerateSection("All computer statistics", () =>
            {
                AddBeginTable("All computer stats");
                AddHeaderText("Domain");
                AddHeaderText("Nb Computer Accounts");
                AddHeaderText("Nb Enabled");
                AddHeaderText("Nb Disabled");
                AddHeaderText("Nb Active");
                AddHeaderText("Nb Inactive");
                AddHeaderText("Nb SidHistory");
                AddHeaderText("Nb Bad PrimaryGroup");
                AddHeaderText("Nb Trusted delegation");
                AddHeaderText("Nb Reversible password");
                AddBeginTableData();
                HealthcheckAccountData total = new HealthcheckAccountData();
                foreach (HealthcheckData data in Report)
                {
                    if (data.ComputerAccountData == null)
                        continue;
                    total.Add(data.ComputerAccountData);
                    AddBeginRow();
                    AddPrintDomain(data.Domain);
                    AddCellNum(data.ComputerAccountData.Number);
                    AddCellNum(data.ComputerAccountData.NumberEnabled);
                    AddCellNum(data.ComputerAccountData.NumberDisabled);
                    AddCellNum(data.ComputerAccountData.NumberActive);
                    AddCellNum(data.ComputerAccountData.NumberInactive);
                    AddCellNum(data.ComputerAccountData.NumberSidHistory);
                    AddCellNum(data.ComputerAccountData.NumberBadPrimaryGroup);
                    AddCellNum(data.ComputerAccountData.NumberTrustedToAuthenticateForDelegation);
                    AddCellNum(data.ComputerAccountData.NumberReversibleEncryption);
                    AddEndRow();
                }
                AddEndTable(() =>
                {
                    AddCellText("Total");
                    AddCellNum(total.Number);
                    AddCellNum(total.NumberEnabled);
                    AddCellNum(total.NumberDisabled);
                    AddCellNum(total.NumberActive);
                    AddCellNum(total.NumberInactive);
                    AddCellNum(total.NumberSidHistory);
                    AddCellNum(total.NumberBadPrimaryGroup);
                    AddCellNum(total.NumberTrustedToAuthenticateForDelegation);
                    AddCellNum(total.NumberReversibleEncryption);
                });
            });
            GenerateConsolidatedOperatingSystemList();
            GenerateConsolidatedOperatingSystemListV2();
        }

        private void GenerateDCInformation()
        {
            GenerateSection("Domain controllers list", () =>
            {
                AddBeginTable("All DC stats");
                AddHeaderText("Domain");
                AddHeaderText("Domain controller");
                AddHeaderText("Operating System");
                AddHeaderText("Creation Date", "Indicates the creation date of the underlying computer object.");
                AddHeaderText("Startup Time");
                AddHeaderText("Uptime");
                AddHeaderText("Owner", "This is the owner of the underlying domain controller object stored in the active directory partition. The nTSecurityDescriptor attribute stores its value.");
                AddHeaderText("Null sessions", "Indicates if an anonymous user can extract information from the domain controller");
                AddHeaderText("SMB v1", "Indicates if the domain controller supports this unsafe SMB v1 network protocol.");
                AddHeaderText("Remote spooler", "Indicates if the spooler service is remotely accessible.");
                AddHeaderText("FSMO role", "Flexible Single Master Operation. Indicates the server responsible for each role.");
                AddBeginTableData();
                HealthcheckAccountData total = new HealthcheckAccountData();
                foreach (HealthcheckData data in Report)
                {
                    if (data.DomainControllers == null)
                        continue;
                    foreach (var dc in data.DomainControllers)
                    {
                        AddBeginRow();
                        AddPrintDomain(data.Domain);
                        AddCellText(dc.DCName);
                        AddCellText(dc.OperatingSystem);
                        AddCellText((dc.CreationDate == DateTime.MinValue ? "Unknown" : dc.CreationDate.ToString("u")));
                        AddCellText((dc.StartupTime == DateTime.MinValue ? (dc.LastComputerLogonDate.AddDays(60) < DateTime.Now ? "Inactive?" : "Unknown") : (dc.StartupTime.AddMonths(6) < DateTime.Now ? dc.StartupTime.ToString("u"): dc.StartupTime.ToString("u"))));
                        AddCellText((dc.StartupTime == DateTime.MinValue ? "" : (DateTime.Now.Subtract(dc.StartupTime)).Days.ToString("D3") + " days"));
                        AddCellText((String.IsNullOrEmpty(dc.OwnerName) ? dc.OwnerSID : dc.OwnerName));
                        AddCellText((dc.HasNullSession ? "YES" : "NO"), true, !dc.HasNullSession);
                        AddCellText((dc.SupportSMB1 ? "YES" : "NO"), true, !dc.SupportSMB1);

                        if (data.version >= new Version(2, 5, 3))
                        {
                            AddCellText((dc.RemoteSpoolerDetected ? "YES" : "NO"), true, !dc.RemoteSpoolerDetected);
                        }
                        else
                        {
                            AddCellText("Not available");
                        }
                        if (data.version >= new Version(2, 7))
                        {
                            Add(@"<Td>");
                            if (dc.FSMO != null)
                            {
                                Add(string.Join(",<br>", dc.FSMO.ConvertAll(x => ReportHelper.Encode(x)).ToArray()));
                            }
                            Add("</Td>");
                        }
                        else
                        {
                            AddCellText("Not available");
                        }
                        AddEndRow();
                    }
                }
                AddEndTable();
            });
        }

        private void GenerateConsolidatedOperatingSystemList()
        {
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
            GenerateSection("Operating systems statistics", () =>
            {
                AddParagraph("This section is about generic OS. To see details about Windows versions, see the next section.");
                AddBeginTable("All Os stats");
                AddHeaderText("Domain");
                foreach (string os in AllOS)
                {
                    AddHeaderText(os);
                }
                AddBeginTableData();
                // maybe not the most perfomant algorithm (n^4) but there is only a few domains to consolidate
                foreach (HealthcheckData data in Report)
                {
                    AddBeginRow();
                    AddPrintDomain(data.Domain);
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
                        if (numberOfOccurence < 0)
                        {
                            AddCellText(null);
                        }
                        else
                        {
                            AddCellNum(numberOfOccurence, true);
                        }
                    }
                    AddEndRow();
                }
                AddEndTable(() =>
                {
                    AddCellText("Total");
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
                        AddCellNum(total);
                    }
                });
                if (SpecificOK.Count > 0)
                {
                    AddBeginTable("OS stats");
                    AddHeaderText("Operating System");
                    AddHeaderText("Nb");
                    AddBeginTableData();
                    foreach (string os in SpecificOK.Keys)
                    {
                        AddBeginRow();
                        AddCellText(os);
                        AddCellNum(SpecificOK[os]);
                        AddEndRow();
                    }
                    AddEndTable();
                }
            });
        }

        private void GenerateConsolidatedOperatingSystemListV2()
        {
            List<string> AllOS = new List<string>();
            foreach (HealthcheckData data in Report)
            {
                if (data.OperatingSystemVersion != null)
                {
                    foreach (HealthcheckOSVersionData os in data.OperatingSystemVersion)
                    {
                        var o = GetOSVersionString(os);
                        if (!AllOS.Contains(o))
                            AllOS.Add(o);
                    }
                }
            }
            AllOS.Sort();
            GenerateSection("Operating systems statistics", () =>
            {
                AddParagraph("This section is about detailled Windows OS version (Service Pack, Windows 10 release, etc)");
                AddBeginTable("Windows Os stats");
                AddHeaderText("Domain");
                foreach (string os in AllOS)
                {
                    AddHeaderText(os);
                }
                AddBeginTableData();
                // maybe not the most perfomant algorithm (n^4) but there is only a few domains to consolidate
                foreach (HealthcheckData data in Report)
                {
                    AddBeginRow();
                    AddPrintDomain(data.Domain);
                    foreach (string os in AllOS)
                    {
                        int numberOfOccurence = -1;
                        if (data.OperatingSystemVersion != null)
                        {
                            foreach (var OS in data.OperatingSystemVersion)
                            {
                                if (GetOSVersionString(OS) == os)
                                {
                                    numberOfOccurence = OS.NumberOfOccurence;
                                    break;
                                }
                            }
                        }
                        if (numberOfOccurence < 0)
                        {
                            AddCellText(null);
                        }
                        else
                        {
                            AddCellNum(numberOfOccurence, true);
                        }
                    }
                    AddEndRow();
                }
                AddEndTable(() =>
                {
                    AddCellText("Total");
                    foreach (string os in AllOS)
                    {
                        int total = 0;
                        foreach (HealthcheckData data in Report)
                        {
                            if (data.OperatingSystemVersion != null)
                            {
                                foreach (var OS in data.OperatingSystemVersion)
                                {
                                    if (GetOSVersionString(OS) == os)
                                    {
                                        total += OS.NumberOfOccurence;
                                        break;
                                    }
                                }
                            }
                        }
                        AddCellNum(total);
                    }
                });
            });
        }
        #endregion computer

        #region admin
        private void GenerateAdminGroupsInformation()
        {
            GenerateSection("Administrator groups statistics", () =>
            {
                AddBeginTable("Admin groups stats");
                AddHeaderText("Domain");
                AddHeaderText("Group Name");
                AddHeaderText("Nb Admins");
                AddHeaderText("Nb Enabled");
                AddHeaderText("Nb Disabled");
                AddHeaderText("Nb Inactive");
                AddHeaderText("Nb PWd never expire");
                AddHeaderText("Nb can be delegated");
                AddHeaderText("Nb external users");
                AddHeaderText("Nb protected users", "This is the number of users in the Protected Users group");
                AddBeginTableData();
                foreach (HealthcheckData data in Report)
                {
                    foreach (HealthCheckGroupData group in data.PrivilegedGroups)
                    {
                        AddBeginRow();
                        AddPrintDomain(data.Domain);
                        AddCellText(group.GroupName);
                        AddCellNum(group.NumberOfMember);
                        AddCellNum(group.NumberOfMemberEnabled);
                        AddCellNum(group.NumberOfMemberDisabled);
                        AddCellNum(group.NumberOfMemberInactive);
                        AddCellNum(group.NumberOfMemberPwdNeverExpires);
                        AddCellNum(group.NumberOfMemberCanBeDelegated);
                        AddCellNum(group.NumberOfExternalMember);
                        if (new Version(data.EngineVersion.Split(' ')[0]) >= new Version(2, 9))
                        {
                            AddCellNum(group.NumberOfMemberInProtectedUsers);
                        }
                        else
                        {
                            AddCellText("N/A");
                        }
                        AddEndRow();
                    }
                }
                AddEndTable();
            });
        }
        #endregion admin

        #region control path
        private void GenerateControlPathsInformation()
        {
            GenerateControlPathsInformationAnomalies();
            GenerateControlPathsInformationTrusts();
        }

        private void GenerateControlPathsInformationAnomalies()
        {
            GenerateSection("Indirect links", () =>
            {
                AddBeginTable("control path indirect links");
                AddHeaderText("Domain", null, 2);
                int numRisk = 0;
                foreach (var objectRisk in (CompromiseGraphDataObjectRisk[])Enum.GetValues(typeof(CompromiseGraphDataObjectRisk)))
                {
                    AddHeaderText(ReportHelper.GetEnumDescription(objectRisk), colspan: 4);
                    numRisk++;
                }
                AddEndRow();
                AddBeginRow();
                for (int i = 0; i < numRisk; i++)
                {
                    AddHeaderText(@"Critical Object Found", "Indicates if critical objects such as everyone, authenticated users or domain users can take control, directly or not, of one of the objects.");
                    AddHeaderText(@"Number of objects with Indirect", "Indicates the count of objects per category having at least one indirect user detected.");
                    AddHeaderText(@"Max number of indirect numbers", "Indicates the maximum on all objects of the number of users having indirect access to the object.");
                    AddHeaderText(@"Max ratio", "Indicates in percentage the value of (number of indirect users / number of direct users) if at least one direct users exists. Else the value is zero.");
                }
                AddBeginTableData();
                foreach (var data in Report)
                {
                    if (data.ControlPaths == null)
                        continue;
                    AddBeginRow();
                    AddPrintDomain(data.Domain);
                    foreach (var objectRisk in (CompromiseGraphDataObjectRisk[])Enum.GetValues(typeof(CompromiseGraphDataObjectRisk)))
                    {
                        bool found = false;
                        if (data.ControlPaths != null && data.ControlPaths.AnomalyAnalysis != null)
                        {
                            foreach (var analysis in data.ControlPaths.AnomalyAnalysis)
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
                        }
                        if (!found)
                        {
                            AddCellText("");
                            AddCellNum(0, true);
                            AddCellNum(0, true);
                            AddCellNum(0, true);
                        }
                    }
                    AddEndRow();
                }
                AddEndTable();
            });
        }

        private void GenerateControlPathsInformationTrusts()
        {
            GenerateSection("Link with other domains", () =>
            {
                AddBeginTable("link with other domains");
                AddHeaderText("Domain", null, 2);
                AddHeaderText("Remote Domain", null, 2);

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
                    AddHeaderText(@"Group", "Number of group impacted by this domain");
                    AddHeaderText("Resolved", "Number of unique SID (account, group, computer, ...) resolved");
                    AddHeaderText("Unresolved", "Number of unique SID (account, group, computer, ...) NOT resolved meaning that the underlying object may have been removed");
                }
                AddBeginTableData();
                foreach (var data in Report)
                {
                    if (data.ControlPaths == null)
                        continue;

                    if (data.ControlPaths != null && data.ControlPaths.Dependancies != null)
                    {
                        foreach (var dependancy in data.ControlPaths.Dependancies)
                        {
                            AddBeginRow();
                            AddPrintDomain(data.Domain);
                            AddPrintDomain(dependancy.Domain);
                            foreach (var typology in (CompromiseGraphDataTypology[])Enum.GetValues(typeof(CompromiseGraphDataTypology)))
                            {
                                bool found = false;
                                foreach (var item in dependancy.Details)
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
                    }
                }
                AddEndTable();
            });
        }
        #endregion control path

        #region trust
        private void GenerateTrustInformation()
        {
            List<string> knowndomains = new List<string>();
            GenerateSection("Discovered domains", () =>
            {
                AddBeginTable("discovered domains");
                AddHeaderText("Domain");
                AddHeaderText("Trust Partner");
                AddHeaderText("Type");
                AddHeaderText("Attribut");
                AddHeaderText("Direction");
                AddHeaderText("SID Filtering active");
                AddHeaderText("TGT Delegation");
                AddHeaderText("Creation");
                AddHeaderText("Is Active ?");
                AddBeginTableData();
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
                        AddBeginRow();
                        AddPrintDomain(data.Domain);
                        AddPrintDomain(trust.Domain);
                        AddCellText(TrustAnalyzer.GetTrustType(trust.TrustType));
                        AddCellText(TrustAnalyzer.GetTrustAttribute(trust.TrustAttributes));
                        AddCellText(TrustAnalyzer.GetTrustDirection(trust.TrustDirection));
                        AddCellText(TrustAnalyzer.GetSIDFiltering(trust));
                        AddCellText(TrustAnalyzer.GetTGTDelegation(trust));
                        AddCellDate(trust.CreationDate);
                        AddCellText(trust.IsActive.ToString());
                        AddEndRow();
                    }
                }
                AddEndTable();
            });
            GenerateSection("Other discovered domains", () =>
            {
                AddBeginTable("other discovered domains");
                AddHeaderText("From");
                AddHeaderText("Reachable domain");
                AddHeaderText("Discovered using");
                AddHeaderText("Netbios");
                AddHeaderText("Creation date");
                AddBeginTableData();
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
                            AddBeginRow();
                            AddPrintDomain(data.Domain);
                            AddCellText(di.DnsName);
                            AddCellText(trust.TrustPartner);
                            AddCellText(di.NetbiosName);
                            AddCellDate(di.CreationDate);
                            AddEndRow();
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
                            AddBeginRow();
                            AddPrintDomain(data.Domain);
                            AddCellText(di.DnsName);
                            AddCellText("Unknown");
                            AddCellText(di.NetbiosName);
                            AddCellText("Unknown");
                            AddEndRow();
                        }
                    }
                }

                AddEndTable();
            });
            // prepare a SID map to locate unknown account
            SortedDictionary<string, string> sidmap = new SortedDictionary<string, string>();
            GenerateSection("SID Map", () =>
            {
                AddBeginTable("SID Map");
                AddHeaderText("Domain");
                AddHeaderText("Domain SID");
                AddBeginTableData();
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
                    AddBeginRow();
                    AddCellText(domain);
                    AddCellText(sidmap[domain]);
                    AddEndRow();
                }
                AddEndTable();
            });
        }
        #endregion trust

        #region anomaly
        private void GenerateAnomalyDetail()
        {
            GenerateSection("List of anomalies", () =>
            {

                AddBeginTable("List of anomalies");
                AddHeaderText("Domain");
                AddHeaderText("Krbtgt");
                AddHeaderText("AdminSDHolder");
                AddHeaderText("DC with null session");
                AddHeaderText("Smart card account not update");
                AddHeaderText("Date LAPS Installed (legacy)");
                AddHeaderText("Date LAPS Installed (new)");
                AddBeginTableData();
                foreach (HealthcheckData data in Report)
                {
                    AddBeginRow();
                    AddPrintDomain(data.Domain);
                    AddCellDate(data.KrbtgtLastChangeDate);
                    AddCellNum(data.AdminSDHolderNotOKCount);
                    AddCellNum(data.DomainControllerWithNullSessionCount);
                    AddCellNum(data.SmartCardNotOKCount);
                    AddCellText((data.LAPSInstalled == DateTime.MaxValue ? "Never" : (data.LAPSInstalled == DateTime.MinValue ? "Not checked" : data.LAPSInstalled.ToString("u"))));
                    AddCellText((data.NewLAPSInstalled == DateTime.MaxValue ? "Never" : (data.NewLAPSInstalled == DateTime.MinValue ? "Not checked" : data.NewLAPSInstalled.ToString("u"))));
                    AddEndRow();
                }
                AddEndTable();
            });
        }
        #endregion anomaly

        #region passwordpolicy
        private void GeneratePasswordPoliciesDetail()
        {
            var dist = new Dictionary<string, IEnumerable<DistributionItem>>();
            foreach (var r in Report)
            {
                if (r.PasswordDistribution != null && r.PasswordDistribution.Count > 0)
                {
                    var value = r.PasswordDistribution.Select(x => new DistributionItem { HigherBound = x.HigherBound, Value = x.Value }).ToList();
                    if (dist.ContainsKey(r.DomainFQDN))
                    {
                        dist[r.DomainFQDN + " - " + r.DomainSid] = value;
                    }
                    else
                    {
                        dist[r.DomainFQDN] = value;
                    }
                }
            }

            if (dist.Count > 0)
            {
                GenerateSection("Password Age Distribution", () =>
                {
                    if (_license.IsBasic())
                    {
                        AddParagraph("This feature is reserved for customers who have <a href='https://www.pingcastle.com/services/'>purchased a license</a>");
                    }
                    else
                    {
                        AddParagraph("Here is the distribution where the password has been changed for the last time. Only enabled user accounts are analyzed (no guest account for example).");
                        AddDistributionSeriesChart(dist, "general");


                        AddBeginTable("Password Distribution");
                        AddHeaderText("Domain");
                        for (int i = 0; i < 36; i++)
                        {
                            AddHeaderText((i * 30) + "-" + ((i + 1) * 30) + " days");
                        }
                        AddHeaderText("Other");
                        AddBeginTableData();
                        foreach (HealthcheckData data in Report)
                        {
                            if (data.PasswordDistribution != null && data.PasswordDistribution.Count > 0)
                            {
                                AddBeginRow();
                                AddPrintDomain(data.Domain);
                                for (int i = 0; i < 36; i++)
                                {
                                    var v = data.PasswordDistribution.Where(x => x.HigherBound == i).FirstOrDefault();
                                    AddCellNum(v == null ? 0 : v.Value);
                                }
                                AddCellNum(data.PasswordDistribution.Where(x => x.HigherBound >= 36).Select(x => x.Value).Sum());
                                AddEndRow();
                            }
                        }
                        AddEndTable();
                    }
                });
            }

            GenerateSection("Password policies", () =>
            {
                AddBeginTable("List of password policies");
                AddHeaderText("Domain");
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
                foreach (HealthcheckData data in Report)
                {
                    if (data.GPPPasswordPolicy != null)
                    {
                        foreach (GPPSecurityPolicy policy in data.GPPPasswordPolicy)
                        {
                            AddBeginRow();
                            AddPrintDomain(data.Domain);
                            AddCellText(policy.GPOName);
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
                }
                AddEndTable();
            });
            GenerateSection("Screensaver policies", () =>
            {
                AddBeginTable("List of screensaver policies");
                AddHeaderText("Domain");
                AddHeaderText("Policy Name");
                AddHeaderText("Screensaver enforced");
                AddHeaderText("Password request");
                AddHeaderText("Start after (seconds)");
                AddHeaderText("Grace Period (seconds)");
                AddBeginTableData();
                foreach (HealthcheckData data in Report)
                {
                    if (data.GPPPasswordPolicy != null)
                    {
                        foreach (GPPSecurityPolicy policy in data.GPOScreenSaverPolicy)
                        {
                            AddBeginRow();
                            AddPrintDomain(data.Domain);
                            AddCellText(policy.GPOName);
                            AddPSOStringValue(policy, "ScreenSaveActive");
                            AddPSOStringValue(policy, "ScreenSaverIsSecure");
                            AddPSOStringValue(policy, "ScreenSaveTimeOut");
                            AddPSOStringValue(policy, "ScreenSaverGracePeriod");
                            AddEndRow();
                        }
                    }
                }
                AddEndTable();
            });
            GenerateSection("Security settings", () =>
            {
                AddBeginTable("List of security settings");
                AddHeaderText("Domain");
                AddHeaderText("Policy Name");
                AddHeaderText("Setting");
                AddHeaderText("Value");
                AddBeginTableData();
                foreach (HealthcheckData data in Report)
                {
                    if (data.GPOLsaPolicy != null)
                    {
                        foreach (GPPSecurityPolicy policy in data.GPOLsaPolicy)
                        {
                            foreach (GPPSecurityPolicyProperty property in policy.Properties)
                            {
                                AddBeginRow();
                                AddPrintDomain(data.Domain);
                                AddCellText(policy.GPOName);
                                Add(@"<td class='text'>");
                                Add(GetLinkForLsaSetting(property.Property));
                                Add(@"</td>");
                                AddLsaSettingsValue(property.Property, property.Value);
                                AddEndRow();
                            }
                        }
                    }
                }
                AddEndTable();
            });
        }
        #endregion passwordpolicy

        #region gpo detail
        private void GenerateGPODetail()
        {
            GenerateSection("Obfuscated Password", () =>
            {
                AddBeginTable("List of obfuscated passwords");
                AddHeaderText("Domain");
                AddHeaderText("GPO Name");
                AddHeaderText("Password origin");
                AddHeaderText("UserName");
                AddHeaderText("Password");
                AddHeaderText("Changed");
                AddHeaderText("Other");
                AddBeginTableData();
                foreach (HealthcheckData data in Report)
                {
                    foreach (GPPPassword password in data.GPPPassword)
                    {
                        AddBeginRow();
                        AddPrintDomain(data.Domain);
                        AddCellText(password.GPOName);
                        AddCellText(password.Type);
                        AddCellText(password.UserName);
                        AddCellText(password.Password);
                        AddCellDate(password.Changed);
                        AddCellText(password.Other);
                        AddEndRow();
                    }
                }
                AddEndTable();
            });
        }
        #endregion gpo detail

        void AddPrintDomain(DomainKey key, string risk = null)
        {
            Add(@"<td class='text'>");
            Add(PrintDomain(key, risk));
            Add(@"</td>");
        }

        new string PrintDomain(DomainKey key, string risk)
        {
            string label = PrintDomainLabel(key);
            if (GetUrlCallbackDomain == null)
                return label;
            string htmlData = GetUrlCallbackDomain(key, label, risk);
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
            if (!string.IsNullOrEmpty(key.DomainName))
                return key.DomainName;
            if (!string.IsNullOrEmpty(key.DomainNetBIOS))
                return "NetBIOS: " + key.DomainNetBIOS;
            if (!string.IsNullOrEmpty(key.DomainSID))
                return "SID: " + key.DomainSID;
            return "Error please contact the support";
        }
    }
}
