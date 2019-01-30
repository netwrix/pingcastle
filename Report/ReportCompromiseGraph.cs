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
using System.ComponentModel;
using System.Reflection;
using System.Text;

namespace PingCastle.Report
{
	public class ReportCompromiseGraph : ReportRiskControls<CompromiseGraphData>, IPingCastleReportUser<CompromiseGraphData>
	{
		private CompromiseGraphData Report;
		private ADHealthCheckingLicense _license;
		private Version version;

		public string GenerateReportFile(CompromiseGraphData report, ADHealthCheckingLicense license, string filename)
		{
			Report = report;
			_license = license;
			version = new Version(Report.EngineVersion.Split(' ')[0]);
			return GenerateReportFile(filename);
		}

		public string GenerateRawContent(CompromiseGraphData report)
		{
			Report = report;
			_license = null;
			version = new Version(Report.EngineVersion.Split(' ')[0]);
			sb.Length = 0;
			GenerateContent();
			return sb.ToString();
		}

		protected override void Hook(StringBuilder sbHtml)
		{
			// full screen graphs
			sbHtml.Replace("<html lang=\"en\">", "<html style=\"height:100%; min-height: 100%;\">");
			sbHtml.Replace("<body>", "<body style=\"height: 100%; min-height: 100%;\">");
		}

		protected override void GenerateTitleInformation()
		{
			sb.Append("PingCastle Compromission Graphs - ");
			sb.Append(DateTime.Now.ToString("yyyy-MM-dd"));
		}

		protected override void GenerateHeaderInformation()
		{
			Add(@"<style>");
			Add(TemplateManager.LoadDatatableCss());
			Add(@"</style>");
			Add(ReportBase.GetStyleSheetTheme());
			
			Add(GetRiskControlStyleSheet());
			Add(GetStyleSheet());
			Add(@"<style type=""text/css"">");
			Add(TemplateManager.LoadVisCss());
			Add(@"</style>");
		}

		private string GetStyleSheet()
		{
			return @"<style type=""text/css"">

.modal{top: 50px;}
.legend_user {background: #80b2ff; border: #0047b2;border-width: 1px;border-style: solid;font-family: monospace;padding:2px;}
.legend_fsp {background: #ffa366; border: #8f3900;border-width: 1px;border-style: solid;font-family: monospace;padding:2px;}
.legend_computer {background: #d65c33; border: #661a00;border-width: 1px;border-style: solid;font-family: monospace;padding:2px;}
.legend_group {background: #70db70; border: #196419;border-width: 1px;border-style: solid;font-family: monospace;padding:2px;}
.legend_ou {background: #cccccc; border: #333333;border-width: 1px;border-style: solid;font-family: monospace;padding:2px;}
.legend_gpo {background: #ad8533; border: #403100;border-width: 1px;border-style: solid;font-family: monospace;padding:2px;}
.legend_unknown {background: #ffffff; border: #a352cc;border-width: 1px;border-style: solid;font-family: monospace;padding:2px;}

.modal-full-screen {
  position: fixed;
  top: 0;
  right: 0;
  bottom: 0;
  left: 0;
  overflow: hidden;
}
.modal-full-screen-dialog {
  position: fixed;
  margin: 0;
  width: 100%;
  max-width: 100%;
  height: 100%;
  padding: 0;
}
.modal-full-screen-content {
  position: absolute;
  top: 0;
  right: 0;
  bottom: 0;
  left: 0;
}
.modal-full-screen-body {
  position: absolute;
  top: 50px;
  bottom: 60px;
  width: 100%;
  font-weight: 300;
  overflow: auto;
}

.modal-full-screen-footer {
  position: absolute;
  right: 0;
  bottom: 0;
  left: 0;
  height: 60px;
  padding: 10px;
}

.card-risk-critical
{
color: #fff !important;
background-color: #f12828; !important;
}
.card-risk-high
{
color: #fff !important;
background-color: #ff6a00; !important;
}
.card-risk-medium
{
color: #fff !important;
background-color: #ffd800; !important;
}
.card-risk-low
{
color: #fff !important;
background-color: #83e043; !important;
}
</style>";
		}

		protected override void GenerateBodyInformation()
		{
			GenerateNavigation("Active Directory Compromission Graph", Report.DomainFQDN, Report.GenerationDate);
			GenerateAbout(@"
<p>This page has been inspired from the tools <a href=""https://github.com/ANSSI-FR/AD-control-paths"">Active Directory Control Paths</a>, <a href=""https://github.com/ANSSI-FR/OVALI"">OVALI</a> and <a href=""https://github.com/BloodHoundAD/BloodHound"">BloodHound</a>.</p>
<p>The goal is to understand if, by doing some actions, a user account can gain more privileges than expected. For example, if a helpdesk user can reset a password account which is the owner of the login script of a domain admin, this user can become domain administrator.</p>
<p>Users, groups and other objects are connected through arrows which explain these links. The more objects there are, the more care should be used to check the highlighted path.</p>
<p>The paths made by PingCastle have known limitations compared to other tools to produce its quick analysis:</p>
<ul>
<li>PingCastle does not check for local server ACL like bloodhound does (file server, etc)</li>
<li>PingCastle does only perform its analysis on a single path direction. The report to understand what a simple user can do is not present.</li>
</ul>
<p><strong>This is a compromise between speed and accuracy.</strong></p>

<p><strong>Generated by <a href=""https://www.pingcastle.com"">Ping Castle</a> all rights reserved</strong></p>
<p>Open source components:</p>
<ul>
<li><a href=""https://getbootstrap.com/"">Bootstrap</a> licensed under the <a href=""https://tldrlegal.com/license/mit-license"">MIT license</a></li>
<li><a href=""https://datatables.net/"">DataTables</a> licensed under the <a href=""https://tldrlegal.com/license/mit-license"">MIT license</a></li>
<li><a href=""https://popper.js.org/"">Popper.js</a> licensed under the <a href=""https://tldrlegal.com/license/mit-license"">MIT license</a></li>
<li><a href=""https://jquery.org"">JQuery</a> licensed under the <a href=""https://tldrlegal.com/license/mit-license"">MIT license</a></li>
<li><a href=""http://visjs.org/"">vis.js</a> licensed under the <a href=""https://tldrlegal.com/license/mit-license"">MIT license</a></li>
</ul>
");
			Add(@"
<div id=""wrapper"" class=""container well"">
<noscript>
	<div class=""alert alert-alert"">
		<p><strong>This report requires javascript.</strong></p>
	</div>
</noscript>
<div class=""row""><div class=""col-lg-12""><h1>" + Report.DomainFQDN + @" - Active Directory Compromission Graph</h1>
			<h3>Date: " + Report.GenerationDate.ToString("yyyy-MM-dd") + @" - Engine version: " + Report.EngineVersion + @"</h3>
</div></div>
<div class=""row"">
	<div class=""col-lg-12"">
			<div class=""alert alert-info"">
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
</div></div>

");
			GenerateContent();
		}

		void GenerateContent()
		{
			GenerateSection("Active Directory Indicators", () => GenerateIndicators(Report, Report.AllRiskRules));
			GenerateSectionStaleObjects();
			GenerateSectionPrivilegedAccounts();
			GenerateSectionTrusts();
			GenerateSectionAnomalies();
			GenerateSectionDetailledAnalysis();
		}

		protected void GenerateObjectivesCard(RiskRuleCategory category)
		{
			RiskModelObjective previousObj = RiskModelObjective.None;
			foreach (var rule in Report.RiskRules)
			{
				if (rule.Category != category)
					continue;
				if (previousObj != rule.Objective)
				{
					if (previousObj != RiskModelObjective.None)
					{
						Add(@"	</ul>
	<div class=""card-body""></div>
</div>");
					}
					else
					{
						Add(@"<div class=""card-deck"">");
					}
					Add(@"
<div class=""card shadow"">
	<div class=""card-header"" >
		<p class=""lead card-text"">");
					AddEncoded(ReportHelper.GetEnumDescription(rule.Objective));
					Add(@"</p>
	</div>
	<ul class=""list-group list-group-flush"">
		");
				}
				Add(@"<li class=""list-group-item ");
				if (!rule.Achieved)
				{
					if (rule.Points >= 75)
					{
						Add("card-risk-critical");
					}
					else if (rule.Points >= 50)
					{
						Add("card-risk-high");
					}
					else if (rule.Points >= 25)
					{
						Add("card-risk-medium");
					}
					else
					{
						Add("card-risk-low");
					}
				}
				Add(@""">");
				if (rule.Achieved)
					Add(@"✓ ");
				else
					Add(@"✗ ");
				AddEncoded(rule.Rationale);
				Add(@"<i class=""float-right"">Risk: ");
				Add(rule.Points);
				Add(@"</i></li>");
				previousObj = rule.Objective;
			}
			if (previousObj != RiskModelObjective.None)
			{
				Add(@"	</ul>
	<div class=""card-body""></div>
</div>");
				Add(@"
</div>
");
			}
		}

		private void GenerateSectionStaleObjects()
		{
			GenerateSection("Stale Objects", () =>
			{
				GenerateSubIndicator("Stale Objects", Report.GlobalScore, Report.StaleObjectsScore, "It is about operations related to user or computer objects");
				GenerateSubSection("Objectives");
				GenerateObjectivesCard(RiskRuleCategory.StaleObjects);
			});
		}

		private void GenerateSectionPrivilegedAccounts()
		{
			GenerateSection("Privileged Accounts", () =>
			{
				GenerateSubIndicator("Privileged Accounts", Report.GlobalScore, Report.PrivilegiedGroupScore, "It is about administrators of the Active Directory");
				GenerateSubSection("Objectives");
				GenerateObjectivesCard(RiskRuleCategory.PrivilegedAccounts);
			});
		}

		private void GenerateSectionTrusts()
		{
			GenerateSection("Trusts", () =>
			{
				GenerateSubIndicator("Trusts", Report.GlobalScore, Report.TrustScore, "It is about operations related to user or computer objects");
				GenerateSubSection("Objectives");
				GenerateObjectivesCard(RiskRuleCategory.Trusts);
				GenerateSubSection("Foreign domains involved");
				if (Report.Dependancies.Count == 0)
				{
					Add(@"<div class=""row""><div class=""col-lg-12""><p>No operative link with other domains has been found.</p></div></div>");
					return;
				}
				Add(@"<div class=""row""><div class=""col-lg-12""><p>The following table lists all the foreign domains whose compromission can impact this domain. The impact is listed by typology of objects.</p></div></div>");
				Add(@"<div class=""row"">
<div class=""col-md-12 table-responsive"">
				<table class=""table table-striped table-bordered sortable-theme-bootstrap"" data-sortable="""">
	<thead>
	<tr>
		<th rowspan=""2"">FQDN</th>
		<th rowspan=""2"">NetBIOS</th>
		<th rowspan=""2"">SID</th>
");
				int numTypology = 0;
				foreach (var typology in (CompromiseGraphDataTypology[])Enum.GetValues(typeof(CompromiseGraphDataTypology)))
				{
					Add(@"<th colspan=""3"">");
					AddEncoded(ReportHelper.GetEnumDescription(typology));
					Add(@"</th>");
					numTypology++;
				}
				Add(@"
	</tr>
");
				Add(@"<tr>");
				for (int i = 0; i < numTypology; i++)
				{
					Add(@"<th>Group&nbsp;<i class=""info-mark"" data-placement=""bottom"" data-toggle=""tooltip"" title="""" data-original-title=""Number of group impacted by this domain"">?</i></th><th>Resolved&nbsp;<i class=""info-mark"" data-placement=""bottom"" data-toggle=""tooltip"" title="""" data-original-title=""Number of unique SID (account, group, computer, ...) resolved"">?</i></th><th>Unresolved&nbsp;<i class=""info-mark"" data-placement=""bottom"" data-toggle=""tooltip"" title="""" data-original-title=""Number of unique SID (account, group, computer, ...) NOT resolved meaning that the underlying object may have been removed"">?</i></th>");
				}
				Add(@"</tr>");
				Add(@"
	</thead>
");
				foreach (var header in Report.Dependancies)
				{
					Add(@"<tr><td>");
					AddEncoded(header.FQDN);
					Add(@"</td><td>");
					AddEncoded(header.Netbios);
					Add(@"</td><td>");
					AddEncoded(header.Sid);
					Add(@"</td>");
					foreach (var typology in (CompromiseGraphDataTypology[])Enum.GetValues(typeof(CompromiseGraphDataTypology)))
					{
						bool found = false;
						foreach (var item in header.Details)
						{
							if (item.Typology != typology)
								continue;
							found = true;
							Add(@"<td>");
							Add(item.NumberOfGroupImpacted);
							Add(@"</td><td>");
							Add(item.NumberOfResolvedItems);
							Add(@"</td><td>");
							Add(item.NumberOfUnresolvedItems);
							Add(@"</td>");
							break;
						}
						if (!found)
						{
							Add(@"<td></td><td></td><td></td>");
						}
					}
					Add(@"</tr>");
				}
				Add(@"
	</table>
</div>
</div>
");
			});
		}

		private void GenerateSectionAnomalies()
		{
			GenerateSection("Anomalies analysis", () =>
			{
				GenerateSubIndicator("Anomalies", Report.GlobalScore, Report.AnomalyScore, "It is about specific security control points");
				GenerateSubSection("Objectives");
				GenerateObjectivesCard(RiskRuleCategory.Anomalies);
				GenerateSubSection("Indirect links");
				Add(@"
		<div class=""row"">
			<div class=""col-md-12 table-responsive"">
				<table class=""table table-striped table-bordered sortable-theme-bootstrap"" data-sortable="""">
					<thead><tr>
");
					Add(@"
<th>Priority to remediate&nbsp;<i class=""info-mark"" data-placement=""bottom"" data-toggle=""tooltip"" title="""" data-original-title=""Indicates a set of objects considered as a priority when establishing a remediation plan."">?</i></th>
<th>Critical Object Found&nbsp;<i class=""info-mark"" data-placement=""bottom"" data-toggle=""tooltip"" title="""" data-original-title=""Indicates if critical objects such as everyone, authenticated users or domain users can take control, directly or not, of one of the objects."">?</i></th>
<th>Number of objects with Indirect&nbsp;<i class=""info-mark"" data-placement=""bottom"" data-toggle=""tooltip"" title="""" data-original-title=""Indicates the count of objects per category having at least one indirect user detected."">?</i></th>
<th>Max number of indirect numbers&nbsp;<i class=""info-mark"" data-placement=""bottom"" data-toggle=""tooltip"" title="""" data-original-title=""Indicates the maximum on all objects of the number of users having indirect access to the object."">?</i></th>
<th>Max ratio&nbsp;<i class=""info-mark"" data-placement=""bottom"" data-toggle=""tooltip"" title="""" data-original-title=""Indicates in percentage the value of (number of indirect users / number of direct users) if at least one direct users exists. Else the value is zero."">?</i></th>");
				Add(@"</tr>");
				Add(@"
					</thead>
					<tbody>
");
				foreach (var objectRisk in (CompromiseGraphDataObjectRisk[])Enum.GetValues(typeof(CompromiseGraphDataObjectRisk)))
				{
					Add(@"<tr><th>");
					AddEncoded(ReportHelper.GetEnumDescription(objectRisk));
					Add(@"</th>");
					bool found = false;
					foreach (var analysis in Report.AnomalyAnalysis)
					{
						if (analysis.ObjectRisk != objectRisk)
							continue;
						found = true;
						Add(@"<td class=""text"">");
						Add((analysis.CriticalObjectFound ? "<span class='unticked'>YES</span>" : "<span class='ticked'>NO</span>"));
						Add(@"</td><td class=""num"">");
						Add(analysis.NumberOfObjectsWithIndirect);
						Add(@"</td><td class=""num"">");
						Add(analysis.MaximumIndirectNumber);
						Add(@"</td><td class=""num"">");
						Add(analysis.MaximumDirectIndirectRatio);
						Add(@"</td>");
						break;
					}
					if (!found)
					{
						Add(@"<td></td><td></td><td></td><td></td>");
					}
					Add(@"</tr>
");
				}
				Add(@"
					</tbody>
				</table>
			</div>
		</div>
");
			});
		}

		private void GenerateSectionDetailledAnalysis()
		{
			GenerateSection("Detailled analysis", () =>
			{
				foreach (var typology in (CompromiseGraphDataTypology[])Enum.GetValues(typeof(CompromiseGraphDataTypology)))
				{
					GenerateSubSection(ReportHelper.GetEnumDescription(typology));
					Add(@"<div class=""row"">
");
					DisplayGroupHeader();
					for (int i = 0; i < Report.Data.Count; i++)
					{
						var data = Report.Data[i];
						if (data.Typology != typology)
							continue;
						GenerateSummary(i, data);
					}
					Add(@"
	</table>
</div>
</div>
");
				}
				Add(@"
</div>
");
				for (int i = 0; i < Report.Data.Count; i++)
				{
					GenerateModalGraph(i);
					GenerateUserModalMember(i);
					GenerateModalIndirectMember(i);
					GenerateModalDependancy(i);
					GenerateModalRules(i);
					GenerateModalComputerMember(i);
					GenerateModalDeletedObjects(i);
				}
			});
		}

		private void GenerateModalRules(int i)
		{
			Add(@"
<!--TAB rules -->
<div class=""modal"" id=""mod-rules-");
			Add(i);
			Add(@""" tabindex=""-1"" role=""dialog"" aria-hidden=""true"">
	<div class=""modal-dialog modal-xl"" role=""dialog"">
		<div class=""modal-content"">
			<div class=""modal-header"">
				<h4 class=""modal-title"">");
			AddEncoded(Report.Data[i].Description);
			Add(@"</h4>
			</div>
			<div class=""modal-body"">
");
			GenerateAccordion("rules" + i, () =>
				{
					foreach (var rule in Report.RiskRules)
					{
						foreach (var impactedAsset in rule.ImpactedAssets)
						{
							if (impactedAsset.AssetName == Report.Data[i].Name)
							{
								GenerateIndicatorPanelDetail(rule, i, impactedAsset);
								break;
							}
						}
					}
				});
			Add(@"
			</div>
			<div class=""modal-footer"">
				<button type=""button"" class=""btn btn-secondary"" data-dismiss=""modal"">Close</button>
			</div>
		</div>
	</div>
</div>
");
		}

		private void GenerateModalDependancy(int i)
		{
			Add(@"
<!--TAB dependancy -->
<div class=""modal"" id=""mod-dependancy-");
			Add(i);
			Add(@""" tabindex=""-1"" role=""dialog"" aria-hidden=""true"">
	<div class=""modal-dialog modal-xl"" role=""dialog"">
		<div class=""modal-content"">
			<div class=""modal-header"">
				<h4 class=""modal-title"">");
			AddEncoded(Report.Data[i].Description);
			Add(@"</h4>
			</div>
			<div class=""modal-body"">
");
			foreach (var dependancy in Report.Data[i].Dependancies)
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
			Add(@"
			</div>
			<div class=""modal-footer"">
				<button type=""button"" class=""btn btn-secondary"" data-dismiss=""modal"">Close</button>
			</div>
		</div>
	</div>
</div>");
		}

		private void GenerateModalIndirectMember(int i)
		{
			Add(@"
<!--TAB indirectmember -->
<div class=""modal"" id=""mod-indirectmember-");
			Add(i);
			Add(@""" tabindex=""-1"" role=""dialog"" aria-hidden=""true"">
	<div class=""modal-dialog modal-xl"" role=""dialog"">
		<div class=""modal-content"">
			<div class=""modal-header"">
				<h4 class=""modal-title"">");
			AddEncoded(Report.Data[i].Description);
			Add(@"</h4>
			</div>
			<div class=""modal-body"">
<div class=""row""><div class=""col-lg-12""><h4>Indirect Members</h4></div></div>
				<div class=""row table-responsive"">
<table class=""table table-striped table-bordered sortable-theme-bootstrap"" data-sortable="""">
<thead><tr> 
	<th>Name</th>
	<th>Security Identifier</th>
	<th>Distance</th>
	<th>Last authorized object</th>
	<th>Path</th>
</tr>
</thead>
<tbody>
");
			foreach (var member in Report.Data[i].IndirectMembers)
			{
				DisplayIndirectMember(member);
			}
			Add(@"
</tbody>
</table>
				</div>
			</div>
			<div class=""modal-footer"">
				<button type=""button"" class=""btn btn-secondary"" data-dismiss=""modal"">Close</button>
			</div>
		</div>
	</div>
</div>
");
		}

		private void GenerateModalDeletedObjects(int i)
		{
			Add(@"
<!--TAB deleted -->
<div class=""modal"" id=""mod-deleted-");
			Add(i);
			Add(@""" tabindex=""-1"" role=""dialog"" aria-hidden=""true"">
	<div class=""modal-dialog modal-xl"" role=""dialog"">
		<div class=""modal-content"">
			<div class=""modal-header"">
				<h4 class=""modal-title"">");
			AddEncoded(Report.Data[i].Description);
			Add(@"</h4>
			</div>
			<div class=""modal-body"">
<div class=""row""><div class=""col-lg-12""><h4>Deleted objects</h4></div></div>
				<div class=""row table-responsive"">
<table class=""table table-striped table-bordered sortable-theme-bootstrap"" data-sortable="""">
<thead><tr> 
	<th>Security Identifier</th>
</tr>
</thead>
<tbody>
");
			foreach (var member in Report.Data[i].DeletedObjects)
			{
				Add(@"<tr>
	<td class='text'>");
			AddEncoded(member.Sid);
			Add(@"</td>
</tr>
");
			}
			Add(@"
</tbody>
</table>
				</div>
			</div>
			<div class=""modal-footer"">
				<button type=""button"" class=""btn btn-secondary"" data-dismiss=""modal"">Close</button>
			</div>
		</div>
	</div>
</div>
");
		}

		private void DisplayIndirectMember(SingleCompromiseGraphIndirectMemberData member)
		{
			Add(@"<tr>
	<td class='text'>");
			AddEncoded(member.Name);
			Add(@"</td>
	<td class='text'>");
			AddEncoded(member.Sid);
			Add(@"</td>
	<td class='num'>");
			Add(member.Distance);
			Add(@"</td>
	<td class='text'>");
			AddEncoded(member.AuthorizedObject);
			Add(@"</td>
	<td class='text'>");
			AddEncoded(member.Path);
			Add(@"</td>
</tr>");
		}

		private void GenerateUserModalMember(int i)
		{
			Add(@"
<!--TAB member -->
<div class=""modal"" id=""mod-member-");
			Add(i);
			Add(@""" tabindex=""-1"" role=""dialog"" aria-hidden=""true"">
	<div class=""modal-dialog modal-xl"" role=""dialog"">
		<div class=""modal-content"">
			<div class=""modal-header"">
				<h4 class=""modal-title"">");
			AddEncoded(Report.Data[i].Description);
			Add(@"</h4>
			</div>
			<div class=""modal-body"">
<div class=""row""><div class=""col-lg-12""><h4>Direct User Members</h4></div></div>
				<div class=""row table-responsive"">
<table class=""table table-striped table-bordered sortable-theme-bootstrap"" data-sortable="""">
<thead><tr> 
	<th>SamAccountName</th>
	<th>Enabled</th>
	<th>Active</th>
	<th>Pwd never Expired</th>
	<th>Locked</th>
	<th>Smart Card required</th>
	<th>Service account</th>
	<th>Flag Cannot be delegated present</th>
	<th>Distinguished name</th>
</tr>
</thead>
<tbody>
");
			foreach (var member in Report.Data[i].DirectUserMembers)
			{
				DisplayUserMember(member);
			}
			Add(@"
</tbody>
</table>
				</div>
			</div>
			<div class=""modal-footer"">
				<button type=""button"" class=""btn btn-secondary"" data-dismiss=""modal"">Close</button>
			</div>
		</div>
	</div>
</div>
");
		}

		private void GenerateModalComputerMember(int i)
		{
			Add(@"
<!--TAB member -->
<div class=""modal"" id=""mod-cmember-");
			Add(i);
			Add(@""" tabindex=""-1"" role=""dialog"" aria-hidden=""true"">
	<div class=""modal-dialog modal-xl"" role=""dialog"">
		<div class=""modal-content"">
			<div class=""modal-header"">
				<h4 class=""modal-title"">");
			AddEncoded(Report.Data[i].Description);
			Add(@"</h4>
			</div>
			<div class=""modal-body"">
<div class=""row""><div class=""col-lg-12""><h4>Direct Computer Members</h4></div></div>
				<div class=""row table-responsive"">
<table class=""table table-striped table-bordered sortable-theme-bootstrap"" data-sortable="""">
<thead><tr> 
	<th>SamAccountName</th>
	<th>Enabled</th>
	<th>Active</th>
	<th>Locked</th>
	<th>Flag Cannot be delegated present</th>
	<th>Distinguished name</th>
</tr>
</thead>
<tbody>
");
			foreach (var member in Report.Data[i].DirectComputerMembers)
			{
				DisplayComputerMember(member);
			}
			Add(@"
</tbody>
</table>
				</div>
			</div>
			<div class=""modal-footer"">
				<button type=""button"" class=""btn btn-secondary"" data-dismiss=""modal"">Close</button>
			</div>
		</div>
	</div>
</div>
");
		}

		private void GenerateModalGraph(int i)
		{
			Add(@"
<!--TAB graph -->
<div class=""modal modal-full-screen"" id=""tab-graph-");
			Add(i);
			Add(@""" tabindex=""-1"" role=""dialog"" aria-hidden=""true"">
	<div class=""modal-dialog  modal-full-screen-dialog"" role=""dialog"">
		<div class=""modal-content modal-full-screen-content"">
			<div class=""modal-header"">
				<h4 class=""modal-title"">");
			AddEncoded(Report.Data[i].Description);
			Add(@"</h4>
			</div>
			<div class=""modal-body modal-full-screen-body"">
				<div class=""progress mt-2 d-none"" id=""progress");
			Add(i);
			Add(@""">
					<div class=""progress-bar"" role=""progressbar"" aria-valuenow=""0"" aria-valuemin=""0"" aria-valuemax=""100"" style=""width: 0%"">
						0%
					</div>
				</div>
				<div id=""mynetwork");
			Add(i);
			Add(@""" class=""fill"" style=""height: 100%; min-height: 100%; border-width:1px;""></div>

				<div style=""position: absolute;top: 55px;left: 0px;"">
					Legend: <br>
					<i class=""legend_user"">u</i> user<br>
					<i class=""legend_fsp"">w</i> external user or group<br>
					<i class=""legend_computer"">m</i> computer<br>
					<i class=""legend_group"">g</i> group<br>
					<i class=""legend_ou"">o</i> OU<br>
					<i class=""legend_gpo"">x</i> GPO<br>
					<i class=""legend_unknown"">?</i> Other
				</div>
			</div>
			<div class=""modal-footer modal-full-screen-footer"">
				<button type=""button"" class=""btn btn-secondary"" data-dismiss=""modal"">Close</button>
			</div>
		</div>
	</div>
</div>");
		}

		void GenerateIndicatorPanelDetail(CompromiseGraphRiskRule rule, int index, CompromiseGraphRiskRuleDetail detail)
		{
			string safeRuleId = rule.RiskId.Replace("$", "dollar");
			GenerateAccordionDetail("rulesdetail" + index + safeRuleId, "rules" + index, detail.Rationale, rule.Points, false,
				() =>
				{

					var hcrule = RuleSet<CompromiseGraphData>.GetRuleFromID(rule.RiskId);
					if (hcrule == null)
					{
					}
					else
					{
						Add("<h3>");
						AddEncoded(hcrule.Title);
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
					if (detail.Details != null && detail.Details.Count > 0)
					{
						Add("<strong>Details:</strong><p>");
						Add(String.Join("<br>\r\n", detail.Details.ToArray()));
						Add("</p>");
					}
				});
		}

		private void DisplayUserMember(SingleCompromiseGraphUserMemberData member)
		{
			Add(@"<tr>
	<td class='text'>");
			AddEncoded(member.Name);
			Add(@"</td>
	<td class='text'>");
			Add((member.IsEnabled ? "<span class='ticked'>&#10003;</span>" : "<span class='unticked'>&#10007;</span>"));
			Add(@"</td>
	<td class='text'>");
			Add((member.IsActive ? "<span class='ticked'>&#10003;</span>" : "<span class='unticked'>&#10007;</span>"));
			Add(@"</td>
	<td class='text'>");
			Add((member.DoesPwdNeverExpires ? "<span class='unticked'>YES</span>" : "<span class='ticked'>NO</span>"));
			Add(@"</td>
	<td class='text'>");
			Add((member.IsLocked ? "<span class='unticked'>YES</span>" : "<span class='ticked'>NO</span>"));
			Add(@"</td>
	<td class='text'>");
			Add((member.SmartCardRequired ? "<span class='ticked'>YES</span>" : "<span>NO</span>"));
			Add(@"</td>
	<td class='text'>");
			Add((member.IsService ? "<span class='unticked'>YES</span>" : "<span>NO</span>"));
			Add(@"</td>
	<td class='text'>");
			Add((!member.CanBeDelegated ? "<span class='ticked'>YES</span>" : "<span class='unticked'>NO</span>"));
			Add(@"</td>
	<td class='text'>");
			AddEncoded(member.DistinguishedName);
			Add(@"</td>
</tr>
");
		}

		private void DisplayComputerMember(SingleCompromiseGraphComputerMemberData member)
		{
			Add(@"<tr>
	<td class='text'>");
			AddEncoded(member.Name);
			Add(@"</td>
	<td class='text'>");
			Add((member.IsEnabled ? "<span class='ticked'>&#10003;</span>" : "<span class='unticked'>&#10007;</span>"));
			Add(@"</td>
	<td class='text'>");
			Add((member.IsActive ? "<span class='ticked'>&#10003;</span>" : "<span class='unticked'>&#10007;</span>"));
			Add(@"</td>
	<td class='text'>");
			Add((member.IsLocked ? "<span class='unticked'>YES</span>" : "<span class='ticked'>NO</span>"));
			Add(@"</td>
	<td class='text'>");
			Add((!member.CanBeDelegated ? "<span class='ticked'>YES</span>" : "<span class='unticked'>NO</span>"));
			Add(@"</td>
	<td class='text'>");
			AddEncoded(member.DistinguishedName);
			Add(@"</td>
</tr>
");
		}

        private void DisplayGroupHeader()
        {
            Add(@"
<div class=""col-md-12 table-responsive"">
				<table class=""table table-striped table-bordered sortable-theme-bootstrap"" data-sortable="""">
	<thead>
	<tr>
		<th>Group or user account&nbsp;<i class=""info-mark"" data-placement=""bottom"" data-toggle=""tooltip"" title="""" data-original-title=""The graph represents the objects which can take control of this group or user account."">?</i></th>
		<th>Priority&nbsp;<i class=""info-mark"" data-placement=""bottom"" data-toggle=""tooltip"" title="""" data-original-title=""Indicates relatively to other objects the importance of this object when establishing a remediation plan. This importance is computed based on the impact and the easiness to proceed."">?</i></th>
		<th>Number of users member of the group&nbsp;<i class=""info-mark"" data-placement=""bottom"" data-toggle=""tooltip"" title=""Indicates the number of local user accounts. Foreign users or groups are excluded."" data-original-title="""">?</i></th>
		<th>Number of computer member of the group&nbsp;<i class=""info-mark"" data-placement=""bottom"" data-toggle=""tooltip"" title=""Indicates the number of local user accounts. Foreign users or groups are excluded."" data-original-title="""">?</i></th>
		<th>Number of object having indirect control&nbsp;<i class=""info-mark"" data-placement=""bottom"" data-toggle=""tooltip"" title=""Indicates the number of local user accounts. Foreign users or groups are excluded."" data-original-title="""">?</i></th>
		<th>Number of unresolved members (removed?)&nbsp;<i class=""info-mark"" data-placement=""bottom"" data-toggle=""tooltip"" title=""Indicates the number of local user accounts. Foreign users or groups are excluded."" data-original-title="""">?</i></th>
		<th>Link with other domains</th>
		<th>Rules triggered</th>
		<th>Detail</th>
	</tr>
	</thead>
");
        }

        private void GenerateSummary(int index, SingleCompromiseGraphData data)
        {
			Add(@"<tr><td>");
			AddEncoded(data.Description);
			Add(@"</td><td>");
			AddEncoded(ReportHelper.GetEnumDescription(data.ObjectRisk));
			Add(@"</td><td>"); 
			if (data.DirectUserMembers.Count > 0)
			{
				Add(data.DirectUserMembers.Count);
				Add(@" <a href=""#mod-member-");
				Add(index);
				Add(@""" data-toggle=""modal"">");
				Add("(Details)");
				Add(@"</a>");
			}
			else
			{
				Add(0);
			}
			Add(@"</td><td>");
			if (data.DirectComputerMembers.Count > 0)
			{
				Add(data.DirectComputerMembers.Count);
				Add(@" <a href=""#mod-cmember-");
				Add(index);
				Add(@""" data-toggle=""modal"">");
				Add("(Details)");
				Add(@"</a>");
			}
			else
			{
				Add(0);
			}
			Add(@"</td><td>");
			if (data.IndirectMembers.Count > 0)
			{
				Add(data.IndirectMembers.Count);
				Add(@" <a href=""#mod-indirectmember-");
				Add(index);
				Add(@""" data-toggle=""modal"">");
				Add("(Details)");
				Add(@"</a>");
			}
			else
			{
				Add(0);
			}
			Add(@"</td><td>");
			if (data.DeletedObjects.Count != 0)
			{
				Add(data.DeletedObjects.Count);
				Add(@" <a href=""#mod-deleted-");
				Add(index);
				Add(@""" data-toggle=""modal"">");
				Add("(Details)");
				Add(@"</a>");
			}
			else
			{
				Add(0);
			}
			Add(@"</td><td>");
			if (data.Dependancies.Count != 0)
			{
				for (int i = 0; i < data.Dependancies.Count; i++)
				{
					var d = data.Dependancies[i];
					if (i > 0)
						Add("<br>");
					Add(@"<a href = ""#mod-dependancy-");
					Add(index);
					Add(@""" data-toggle=""modal"">");
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
			}
			else
			{
				Add(@"None");
			}
			Add(@"</td><td>");
			int ruleCount = 0;
			foreach(var rule in Report.RiskRules)
			{
				foreach (var impactedAsset in rule.ImpactedAssets)
				{
					if (impactedAsset.AssetName == data.Name)
					{
						ruleCount++;
						break;
					}
				}
			}
			if (ruleCount == 0)
			{
				Add(@"<span class=""ticked"">0 rule triggered</span>");
			}
			else
			{
				Add(@"<span class=""unticked""><a href=""#mod-rules-");
				Add(index);
				Add(@""" data-toggle=""modal"">");
				Add(ruleCount);
				Add(" rule(s) triggered</a></span>");
			}
			Add(@"</td><td><a href=""#tab-graph-");
            Add(index);
            Add(@""" data-toggle=""modal"">Analysis");
            Add(@"</a></td></tr>");
        }

        protected override void GenerateFooterInformation()
		{
			Add(@"
<script>
");
			Add(TemplateManager.LoadJqueryDatatableJs());
			Add(TemplateManager.LoadDatatableJs());
			Add(TemplateManager.LoadVisJs());
			Add(@"
$('table').not('.model_table').DataTable(
    {
        'paging': false,
        'searching': false
    }
);

    function getTooltipHtml(d) {
        var output = '<b>' + d.shortName + '</b>';
        output += '<br/>' + d.name;
		if (d.type != null)
			output += '<br/>type: ' + d.type;
		if (d.suspicious == 1)
			output += '<br/><b>suspicious</b>';
        return output;
    }

    var colors = {
        'default': {background: ""#CCCCCC"", border: ""#212121"", highlight: {background: ""#CCCCCC"", border: ""#212121""}},
		suspicious: {background: ""#ff6a00"", border: ""#f12828"", highlight: {background: ""#ff6a00"", border: ""#f12828""}},
		critical: {background: ""#f12828"", border: ""#f12828"", highlight: {background: ""#f12828"", border: ""#f12828""}},
		user: {background: ""#80b2ff"", border: ""#0047b2"", highlight: {background: ""#80b2ff"", border: ""#0047b2""}},
		inetorgperson: {background: ""#80b2ff"", border: ""#0047b2"", highlight: {background: ""#80b2ff"", border: ""#0047b2""}},
		foreignsecurityprincipal: {background: ""#ffa366"", border: ""#8f3900"", highlight: {background: ""#ffa366"", border: ""#8f3900""}},
		computer: {background: ""#d65c33"", border: ""#661a00"", highlight: {background: ""#d65c33"", border: ""#661a00""}},
		group: {background: ""#70db70"", border: ""#196419"", highlight: {background: ""#70db70"", border: ""#196419""}},
		organizationalunit: {background: ""#cccccc"", border: ""#333333"", highlight: {background: ""#cccccc"", border: ""#333333""}},
		container: {background: ""#cccccc"", border: ""#333333"", highlight: {background: ""#cccccc"", border: ""#333333""}},
		organizationalunit: {background: ""#cccccc"", border: ""#333333"", highlight: {background: ""#cccccc"", border: ""#333333""}},
		domaindns: {background: ""#cccccc"", border: ""#333333"", highlight: {background: ""#cccccc"", border: ""#333333""}},
		builtindomain: {background: ""#cccccc"", border: ""#333333"", highlight: {background: ""#cccccc"", border: ""#333333""}},
		grouppolicycontainer: {background: ""#ad8533"", border: ""#403100"", highlight: {background: ""#ad8533"", border: ""#403100""}},
		file: {background: ""#e680ff"", border: ""#8e00b2"", highlight: {background: ""#e680ff"", border: ""#8e00b2""}},
		unknown: {background: ""#ffffff"", border: ""#a352cc"", highlight: {background: ""#ffffff"", border: ""#a352cc""}},
    };
	var symbols = {
		'default': '-',
		user: 'u',
		inetorgperson: 'u',
		foreignsecurityprincipal: 'w',
		computer: 'm',
		group: 'g',
		organizationalunit: 'o',
		container: 'o',
		domaindns: 'o',
		builtindomain: 'o',
		grouppolicycontainer: 'x',
		file: 'f',
		unknown: '?',
	};

    function carto(data, id) {
        var nodes = new vis.DataSet();
        var edges = new vis.DataSet();



        for (var i = 0; i < data.nodes.length; i++) {
            var n = data.nodes[i], node;

            node = {
                        // we use the count of the loop as an id if the id property setting is false
                        // this is in case the edges properties 'from' and 'to' are referencing
                        // the order of the node, not the real id.
                        id: n['id'],
                shortName: n['shortName'],
				suspicious: n['suspicious'],
                value: null === n['dist'] ? 50 : ( n['critical'] == 1 ? 25 : 1),
                label: (n['type'] in symbols ? symbols[n['type']] : symbols['unknown']),
                title: getTooltipHtml(n),
				shape: null === n['dist'] ? 'box':'ellipse',
                color: n['critical'] == 1 ? colors['critical'] :(n['suspicious'] == 1 ? colors['suspicious'] : (n['type'] in colors ? colors[n['type']] : colors['unknown']))
            };
            nodes.add(node);
        }
        for (var j = 0; j < data.links.length; j++) {
            var l = data.links[j];
            var edge = {
                        from: l.source,
                to: l.target,
                data: {
                        rels: l.rels,
                    /*fromShortName: nodes.get(l.source).shortName,
                    fromBaseGroup: nodes.get(l.source).baseGroup,
                    toShortName: nodes.get(l.target).shortName,
                    toBaseGroup: nodes.get(l.target).baseGroup,*/
                    type: l.type
                },
                arrows: l.type === 'double' ? 'to, from' : 'to',
                title: l.rels.join('<br>'),
                color: {color: l.color, highlight: l.color, hover: l.color }
            };

            edges.add(edge);
        }

        // create a network
        var container = document.getElementById('mynetwork' + id);
        var networkData = {
            nodes: nodes,
            edges: edges
        };

        // create an array with nodes
        var options = {
            height: '100%',
            autoResize: true,
            layout:
            {
                            improvedLayout: false
            },
            nodes: {
                            // you can use 'box', 'ellipse', 'circle', 'text' or 'database' here
                            // 'ellipse' is the default shape.
                size: 20,
                font: {
                            //size: 15,
                            color: '#000000',
                    //face: 'arial' // maybe use a monospaced font?
                },
                borderWidth: 1,
                borderWidthSelected: 3,
                scaling: {
                            label: {
                            min: 15,
                        max: 50
                    }
                }
            },
            edges: {
                            width: 2,
                smooth: {
                            type: 'continuous'
                },
                hoverWidth: 2,
                selectionWidth: 2,
                arrows: {
                        to: {
                        enabled: true,
                        scaleFactor: 0.5
                    }, from: {
                        enabled: false,
                        scaleFactor: 0.5
                    }
                },
                color: {
                    //      inherit: 'from',
                    color: '#666666',
                    hover: '#333333',
                    highlight: '#000000'
                }
            },
            interaction: {
                multiselect: true,
                hover: true,
                hideEdgesOnDrag: true
            }
        };

        options.physics = {
            stabilization: {
                iterations: 2000 // try to stabilize the graph in 2000 times, after that show it anyway
            },
            barnesHut: {
                gravitationalConstant: -2000,
                centralGravity: 0.1,
                springLength: 95,
                springConstant: 0.04,
                damping: 0.09
            },
            enabled: true
        };
                        
        var network = new vis.Network(container, networkData, options);
        network.data = networkData;

        return network;
    }

");
			for (int i = 0; i < Report.Data.Count; i++)
			{
				Add(@"
$('#tab-graph-");
				Add(i);
				Add(@"').on('shown.bs.modal', function () {


	if(document.getElementById('mynetwork' + ");
				Add(i);
				Add(@").childNodes.length != 0)
		return;

	var network;

	var data = ");
				Add(BuildJasonFromSingleCompromiseGraph(Report.Data[i]));
				Add(@";
	var progressBar = $('#progress");
				Add(i);
				Add(@"');
	if (data.nodes.length > 0)
			progressBar.removeClass('d-none');

	network = carto(data,");
				Add(i);
				Add(@");
	

		network.on('stabilizationProgress', function (params) {
			var percentVal = 100 * params.iterations / params.total;
			progressBar.find('.progress-bar').css('width', percentVal + '%').attr('aria-valuenow', percentVal + '%').text(percentVal + '%');
		});
		network.once('stabilizationIterationsDone', function () {
			var percentVal = 100;
			progressBar.find('.progress-bar').css('width', percentVal + '%').attr('aria-valuenow', percentVal + '%').text(percentVal + '%');
			// really clean the dom element
			progressBar.addClass('d-none');
		});
	});
");

			}
			Add(@"
$(function () {
	$('[data-toggle=""tooltip""]').tooltip({html: true, container: 'body'});
});
</script>
");
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
				for (int j = 0; j < relation.Hints.Count; j++)
				{
					output.Append("         \"" + data.Links[i].Hints[j] + "\"" + (j == relation.Hints.Count - 1 ? String.Empty : ","));
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

	}
}
