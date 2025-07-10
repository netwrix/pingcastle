//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;
using System;
using System.Collections.Generic;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-AuditDC", RiskRuleCategory.Anomalies, RiskModelCategory.Audit)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 10)]
    [RuleIntroducedIn(2, 8)]
    [RuleMaturityLevel(3)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.Audit)]
    public class HeatlcheckRuleAnomalyAuditDC : RuleBase<HealthcheckData>
    {
        private class RequiredSimple
        {
            public string Description { get; set; }
            public string Why { get; set; }
            public bool Success { get; set; }
            public bool Failure { get; set; }
            public bool CheckSuccess { get; set; }
            public bool CheckFailure { get; set; }
            public bool CheckExcludeSuccess { get; set; }
            public bool CheckExcludeFailure { get; set; }
            public bool Simple { get; set; }

            public RequiredSimple(string description, string why, bool simple, bool success = true, bool failure = false)
            {
                Why = why;
                if (string.IsNullOrEmpty(Why))
                    Why = "To be defined";
                Description = description;
                Success = success;
                Failure = failure;
                Simple = simple;
            }

            internal void ReportGPOAuditSimple(int value)
            {
                if (value == 1 || value == 3)
                    CheckSuccess = true;
                if (value == 2 || value == 3)
                    CheckFailure = true;
                if (value == 4)
                {
                    CheckExcludeFailure = true;
                    CheckExcludeSuccess = true;
                }
            }

            public string IsObjectiveAchived()
            {
                if (Success)
                {
                    if (!CheckSuccess)
                        return "No GPO check for audit success";
                    if (CheckSuccess && CheckExcludeSuccess)
                        return "A GPO check for success but another excludes auditing success";
                }
                if (Failure)
                {
                    if (!CheckFailure)
                        return "No GPO check for audit failure";
                    if (CheckFailure && CheckExcludeFailure)
                        return "A GPO check for failure but another excludes auditing failure";
                }
                return null;
            }
        }

        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            var auditToHavePerDC = new Dictionary<string, Dictionary<string, RequiredSimple>>(StringComparer.OrdinalIgnoreCase);
            foreach (var dc in healthcheckData.DomainControllers)
            {
                auditToHavePerDC.Add(dc.DistinguishedName,
                    new Dictionary<string, RequiredSimple>(StringComparer.OrdinalIgnoreCase)
                    {
                        {"0CCE9230-69AE-11D9-BED3-505054503030", new RequiredSimple("Policy Change / Authentication Policy Change", "Collect events 4713, 4716, 4739, 4867, to track trust modifications", false)},
                        {"0CCE9236-69AE-11D9-BED3-505054503030", new RequiredSimple("Account Management / Computer Account Management", "Collect events 4741, 4742 to track computer changes", false)},
                        {"0CCE922D-69AE-11D9-BED3-505054503030", new RequiredSimple("Detailed Tracking / DPAPI Activity", "Collect event 4692 to track the export of DPAPI backup key", false)},
                        {"0CCE9242-69AE-11D9-BED3-505054503030", new RequiredSimple("Account Logon / Kerberos Authentication Service", "Collect events 4768, 4771 for kerberos authentication", false)},
                        {"0CCE9240-69AE-11D9-BED3-505054503030", new RequiredSimple("Account Logon / Kerberos Service Ticket Operations", "Collect events 4769 for kerberos authentication", false)},
                        {"0CCE9216-69AE-11D9-BED3-505054503030", new RequiredSimple("Logon/Logoff / Logoff", "Collect events 4634 for account logoff", false)},
                        {"0CCE9215-69AE-11D9-BED3-505054503030", new RequiredSimple("Logon/Logoff / Logon", "Collect events 4624, 4625, 4648 for account logon", false)},
                        {"0CCE922B-69AE-11D9-BED3-505054503030", new RequiredSimple("Detailed Tracking / Process Creation", "Collect event 4688 to get the history of executed programs", false)},
                        {"0CCE9237-69AE-11D9-BED3-505054503030", new RequiredSimple("Account Management / Security Group Management", "Collect events 4728, 4732, 4756 for group membership change", false)},
                        {"0CCE9211-69AE-11D9-BED3-505054503030", new RequiredSimple("System / Security System Extension", "Collect events 4610, 4697 to track lsass security packages and services", false)},
                        {"0CCE9228-69AE-11D9-BED3-505054503030", new RequiredSimple("Privilege Use / Sensitive Privilege Use", "Collect events 4672, 4673, 4674 for privileges tracking such as the debug one", false)},
                        {"0CCE921B-69AE-11D9-BED3-505054503030", new RequiredSimple("Logon/Logoff / Special Logon", "Collect event 4964 for special group attributed at logon", false)},
                        {"0CCE9235-69AE-11D9-BED3-505054503030", new RequiredSimple("Account Management / User Account Management", "Collect events 4720,22,23,38,65,66,80,94 for user account mamangement", false)},
                    }
                );
            }

            if (healthcheckData.GPOAuditSimple != null)
            {
                foreach (var a in healthcheckData.GPOAuditSimple)
                {
                    foreach (var dc in healthcheckData.DomainControllers)
                    {
                        if (auditToHavePerDC[dc.DistinguishedName].ContainsKey(a.Category))
                        {
                            if (IsGPOAppliedToDC(healthcheckData, dc.DistinguishedName, a))
                            {
                                auditToHavePerDC[dc.DistinguishedName][a.Category].ReportGPOAuditSimple(a.Value);
                            }
                        }
                    }
                }
            }
            if (healthcheckData.GPOAuditAdvanced != null)
            {
                foreach (var a in healthcheckData.GPOAuditAdvanced)
                {
                    foreach (var dc in healthcheckData.DomainControllers)
                    {
                        if (auditToHavePerDC[dc.DistinguishedName].ContainsKey(a.SubCategory.ToString()))
                        {
                            if (IsGPOAppliedToDC(healthcheckData, dc.DistinguishedName, a))
                            {
                                auditToHavePerDC[dc.DistinguishedName][a.SubCategory.ToString()].ReportGPOAuditSimple(a.Value);
                            }
                        }
                    }
                }
            }
            foreach (var dc in healthcheckData.DomainControllers)
            {
                foreach (var audit in auditToHavePerDC[dc.DistinguishedName].Values)
                {
                    var r = audit.IsObjectiveAchived();
                    if (!string.IsNullOrEmpty(r))
                    {
                        AddRawDetail(audit.Simple ? "Simple" : "Advanced", audit.Description, r, audit.Why, dc.DCName);
                    }
                }
            }
            return null;
        }

        static bool IsGPOAppliedToDC(HealthcheckData healthcheckData, string DCdn, IGPOReference g)
        {
            if (healthcheckData.GPOInfoDic.ContainsKey(g.GPOId))
            {
                var gpo = healthcheckData.GPOInfoDic[g.GPOId];
                foreach (var ou in gpo.AppliedTo)
                {
                    if (DCdn.EndsWith(ou))
                    {
                        return true;
                    }
                }
            }
            return false;
        }
    }
}
