//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Healthcheck.Rules;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace PingCastle.Healthcheck
{
    
    public class HealthcheckRules
    {
        private static List<HeatlcheckRuleBase> _rules = null;

        public static List<HeatlcheckRuleBase> Rules {
            get
            {
                if (_rules == null)
                {
                    _rules = LoadRules();
                }
                return _rules;
            }
        }
        private static List<HeatlcheckRuleBase> LoadRules()
        {
			// important: to work with W2000, we cannot use GetType because it will instanciate .Net 3.0 class then load the missing assembly
			// the trick here is to check only the exported type and put as internal the class using .Net 3.0 functionalities
            var output = new List<HeatlcheckRuleBase>();
			foreach (Type type in Assembly.GetAssembly(typeof(HealthcheckRules)).GetExportedTypes())
            {
                if (type.IsSubclassOf(typeof(HeatlcheckRuleBase)))
                {
                    output.Add((HeatlcheckRuleBase)Activator.CreateInstance(type));
                }
            }
            return output;
        }

        // when multiple reports are ran each after each other, internal state can be kept
        void ReInitRule(HeatlcheckRuleBase rule)
        {
            rule.Initialize();
        }

        public void ComputeRiskRules(HealthcheckData healthcheckData)
        {
            healthcheckData.RiskRules = new List<HealthcheckRiskRule>();
            Trace.WriteLine("Begining to run risk rule");
            foreach (HeatlcheckRuleBase rule in Rules)
            {
				Trace.WriteLine("Rule: " + rule.GetType().ToString());
				ReInitRule(rule);
                if (rule.Analyze(healthcheckData))
                {
                    Trace.WriteLine("  matched");
                    HealthcheckRiskRule risk = new HealthcheckRiskRule();
                    risk.Points = rule.Points;
                    risk.Category = rule.Category;
					risk.Model = rule.Model;
                    risk.RiskId = rule.Id;
                    risk.Rationale = rule.Rationale;
                    risk.Details = rule.Details;
                    healthcheckData.RiskRules.Add(risk);
                }
            }
            Trace.WriteLine("Risk rule run stopped");
            ReComputeTotals(healthcheckData);
        }
        public static void ReComputeTotals(HealthcheckData healthcheckData)
        {
            // consolidate scores
            healthcheckData.GlobalScore = 0;
            healthcheckData.StaleObjectsScore = 0;
            healthcheckData.PrivilegiedGroupScore = 0;
            healthcheckData.TrustScore = 0;
            healthcheckData.AnomalyScore = 0;
            foreach (HealthcheckRiskRule rule in healthcheckData.RiskRules)
            {
                switch (rule.Category)
                {
                    case HealthcheckRiskRuleCategory.Anomalies:
                        healthcheckData.AnomalyScore += rule.Points;
                        break;
                    case HealthcheckRiskRuleCategory.PrivilegedAccounts:
                        healthcheckData.PrivilegiedGroupScore += rule.Points;
                        break;
                    case HealthcheckRiskRuleCategory.StaleObjects:
                        healthcheckData.StaleObjectsScore += rule.Points;
                        break;
                    case HealthcheckRiskRuleCategory.Trusts:
                        healthcheckData.TrustScore += rule.Points;
                        break;
                }
            }
            // limit to 100
            if (healthcheckData.StaleObjectsScore > 100)
                healthcheckData.StaleObjectsScore = 100;
            if (healthcheckData.PrivilegiedGroupScore > 100)
                healthcheckData.PrivilegiedGroupScore = 100;
            if (healthcheckData.TrustScore > 100)
                healthcheckData.TrustScore = 100;
            if (healthcheckData.AnomalyScore > 100)
                healthcheckData.AnomalyScore = 100;
            // max of all scores
            healthcheckData.GlobalScore = Math.Max(healthcheckData.StaleObjectsScore,
                                            Math.Max(healthcheckData.PrivilegiedGroupScore,
                                            Math.Max(healthcheckData.TrustScore, healthcheckData.AnomalyScore)));
        }

		/*
        public void GenerateRuleDescriptionFile(string filename)
        {
            Microsoft.Office.Interop.Excel.Application xlApp = new Microsoft.Office.Interop.Excel.Application();
            if (xlApp == null)
            {
                Trace.WriteLine("Excel not installed");
                string output = null;
                output += "\"Id\"\t\"Category\"\t\"Points\"\t\"Description\"\t\"Solution\"\r\n";
                foreach (HeatlcheckRuleBase rule in Rules)
                {
                    output += "\"" + rule.Id + "\"\t\"" + rule.Category.ToString() + "\"\t" + rule.Points + "\t\"" + rule.Description.Replace("\"", "\"\"") + "\"\t\"" + rule.Solution.Replace("\"", "\"\"") + "\"\r\n";
                }
                File.WriteAllText(filename, output);
                throw new InvalidOperationException("Excel cannot be found - using txt output instead");
            }
            try
            {
                // excel save by default to documents
                string fullPath = new FileInfo(filename).FullName;
                xlApp.Visible = false;

                Workbook wb = xlApp.Workbooks.Add(XlWBATemplate.xlWBATWorksheet);
                Worksheet ws = (Worksheet)wb.Worksheets[1];

                ws.Name = "hc-rule";
                ws.Cells[1, 1] = "ID";
                ws.Cells[1, 2] = "Category";
                ws.Cells[1, 3] = "Points";
                ws.Cells[1, 4] = "Description";
                ws.Cells[1, 5] = "Solution";
                int i = 2;
                foreach (HeatlcheckRuleBase rule in Rules)
                {
                    ws.Cells[i, 1] = rule.Id;
                    ws.Cells[i, 2] = rule.Category.ToString();
                    ws.Cells[i, 3] = rule.Points;
                    ws.Cells[i, 4] = rule.Description;
                    ws.Cells[i, 5] = rule.Solution;
                    i++;
                    ws.Columns.AutoFit();
                }
                ws.Rows.AutoFit();
                Range tRange = ws.get_Range(ws.Cells[1, 1], ws.Cells[i - 1, 5]);
                ws.ListObjects.Add(XlListObjectSourceType.xlSrcRange, tRange,
                    Type.Missing, XlYesNoGuess.xlYes, Type.Missing).Name = "RuleTable";
                ws.ListObjects["RuleTable"].TableStyle = "TableStyleMedium3";
                xlApp.DisplayAlerts = false;
                wb.SaveAs(Filename: fullPath);
                xlApp.DisplayAlerts = true;
                xlApp.Quit();
            }
            catch (Exception)
            {
                xlApp.Visible = true;
                throw;
            }
        }
		*/

        public static string GetRuleDescription(string ruleid)
        {
            foreach (var rule in Rules)
            {
                if (rule.Id == ruleid)
                {
                    return rule.Title;
                }
            }
            return String.Empty;
        }

        public static HeatlcheckRuleBase GetRuleFromID(string ruleid)
        {
            foreach (var rule in Rules)
            {
                if (rule.Id == ruleid)
                {
                    return rule;
                }
            }
            return null;
        }
    }
}
