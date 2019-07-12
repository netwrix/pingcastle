using PingCastle.Healthcheck;
using PingCastle.Rules;
using System;
using System.Collections.Generic;
using System.Text;

namespace PingCastle.Report
{
	public class ReportHealthCheckSingleCompared : ReportHealthCheckSingle
	{
		HealthcheckData[] Reports;
		Version[] versions;

		public string GenerateRawContent(HealthcheckData[] reports)
		{
			Reports = reports;
			versions = new Version[2];
			versions[0] = new Version(reports[0].EngineVersion.Split(' ')[0]);
			versions[1] = new Version(reports[1].EngineVersion.Split(' ')[0]);
			sb.Length = 0;
			GenerateContent();
			return sb.ToString();
		}

		private void GenerateContent()
		{
			GenerateSection("Active Directory Indicators", () =>
			{
				GenerateIndicators(Report, Report.AllRiskRules);
			});

			List<RuleBase<HealthcheckData>> applicableRules = GenerateListOfApplicableRules();

			GenerateSection("Stale Objects", () =>
			{
				GenerateSubIndicator("Stale Objects", Report.GlobalScore, Report.StaleObjectsScore, "It is about operations related to user or computer objects");
				GenerateIndicatorPanel("DetailStale", "Stale Objects rule details", RiskRuleCategory.StaleObjects, Report.RiskRules, applicableRules);
			});
			GenerateSection("Privileged Accounts", () =>
			{
				GenerateSubIndicator("Privileged Accounts", Report.GlobalScore, Report.PrivilegiedGroupScore, "It is about administrators of the Active Directory");
				GenerateIndicatorPanel("DetailPrivileged", "Privileged Accounts rule details", RiskRuleCategory.PrivilegedAccounts, Report.RiskRules, applicableRules);
			});
			GenerateSection("Trusts", () =>
			{
				GenerateSubIndicator("Trusts", Report.GlobalScore, Report.TrustScore, "It is about operations related to user or computer objects");
				GenerateIndicatorPanel("DetailTrusts", "Trusts rule details", RiskRuleCategory.Trusts, Report.RiskRules, applicableRules);
			});
			GenerateSection("Anomalies analysis", () =>
			{
				GenerateSubIndicator("Anomalies", Report.GlobalScore, Report.AnomalyScore, "It is about specific security control points");
				GenerateIndicatorPanel("DetailAnomalies", "Anomalies rule details", RiskRuleCategory.Anomalies, Report.RiskRules, applicableRules);
			});
			GenerateSection("Domain Information", GenerateDomainInformation);
			GenerateSection("User Information", GenerateUserInformation);
			GenerateSection("Computer Information", GenerateComputerInformation);
			GenerateSection("Admin Groups", GenerateAdminGroupsInformation);
			GenerateSection("Trusts", GenerateTrustInformation);
			GenerateSection("Anomalies", GenerateAnomalyDetail);
			GenerateSection("Password Policies", GeneratePasswordPoliciesDetail);
			GenerateSection("GPO", GenerateGPODetail);
		}

		protected new void GenerateSection(string title, GenerateContentDelegate generateContent)
		{
			Report = Reports[0];
			version = versions[0];
			base.GenerateSection(title + " - " + Report.GenerationDate.ToString("u"), generateContent);
			Report = Reports[1];
			version = versions[1];
			base.GenerateSection(title + " - " + Report.GenerationDate.ToString("u"), generateContent);
		}
	}
}
