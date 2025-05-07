using PingCastle.Healthcheck;
using PingCastle.PingCastleLicense;

//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection;

namespace PingCastle.Rules
{
    public class RuleSet<T> where T : IRiskEvaluation
    {
        private static Dictionary<string, RuleBase<T>> _cachedRules = null;

        public IInfrastructureSettings InfrastructureSettings { get; set; }

        public static IEnumerable<RuleBase<T>> Rules
        {
            get
            {
                if (_cachedRules == null || _cachedRules.Count == 0)
                {
                    ReloadRules();
                }
                return _cachedRules.Values;
            }
        }

        public static void ReloadRules()
        {
            _cachedRules = new Dictionary<string, RuleBase<T>>();
            LoadRules(_cachedRules);
        }

        public static void LoadRules(Dictionary<string, RuleBase<T>> rules)
        {
            // important: to work with W2000, we cannot use GetType because it will instanciate .Net 3.0 class then load the missing assembly
            // the trick here is to check only the exported type and put as internal the class using .Net 3.0 functionalities
            foreach (Type type in Assembly.GetAssembly(typeof(RuleSet<T>)).GetExportedTypes())
            {
                if (type.IsSubclassOf(typeof(RuleBase<T>)) && !type.IsAbstract)
                {
                    try
                    {
                        var a = (RuleBase<T>)Activator.CreateInstance(type);
                        rules.Add(a.RiskId, a);
                    }
                    catch (Exception)
                    {
                        Trace.WriteLine("Unable to instanciate the type " + type);
                        throw;
                    }
                }
            }
        }

        public static void LoadCustomRules()
        {
            // force the load of rules
            var output = Rules;

            try
            {
                var customRules = CustomRulesSettings.GetCustomRulesSettings();
                if (customRules.CustomRules != null)
                {
                    foreach (CustomRuleSettings rule in customRules.CustomRules)
                    {
                        var riskId = rule.RiskId;
                        RuleBase<T> matchedRule = GetRuleFromID(riskId);
                        if (matchedRule == null)
                        {
                            Trace.WriteLine("Rule computation does not match an existing ID (" + riskId + ")");
                            continue;
                        }
                        if (rule.Computations != null)
                        {
                            matchedRule.RuleComputation.Clear();
                            foreach (CustomRuleComputationSettings c in rule.Computations)
                            {
                                matchedRule.RuleComputation.Add(c.GetAttribute());
                            }
                        }
                        if (rule.MaturityLevel != 0)
                        {
                            matchedRule.MaturityLevel = rule.MaturityLevel;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occured while loading custom rules: " + ex.Message);
                Trace.WriteLine("Unable to load custom rules");
                var e = ex;
                while (e != null)
                {
                    Trace.WriteLine("Exception: " + ex.Message);
                    Trace.WriteLine("StackTrace: " + ex.StackTrace);
                    e = e.InnerException;
                }
            }
        }

        // when multiple reports are ran each after each other, internal state can be kept
        void ReInitRule(RuleBase<T> rule)
        {
            rule.Initialize();
        }

        public List<RuleBase<T>> ComputeRiskRules(T data)
        {
            var output = new List<RuleBase<T>>();
            Trace.WriteLine("Begining to run risk rule");
            foreach (var rule in Rules)
            {
                string ruleName = rule.GetType().ToString();
                Trace.WriteLine("Rule: " + ruleName);
                try
                {
                    ReInitRule(rule);
                    rule.InfrastructureSettings = InfrastructureSettings;
                    if (rule.Analyze(data))
                    {
                        Trace.WriteLine("  matched");
                        output.Add(rule);
                    }
                }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("An exception occured when running the rule : " + ruleName);
                    Trace.WriteLine("An exception occured when running the rule : " + ruleName);
                    DisplaySupportMessage();
                    Console.ResetColor();
                    Console.WriteLine("Message: " + ex.Message);
                    Trace.WriteLine("Message: " + ex.Message);
                    Console.WriteLine("StackTrace: " + ex.StackTrace);
                    Trace.WriteLine("StackTrace: " + ex.StackTrace);
                    if (ex.InnerException != null)
                    {
                        Console.WriteLine("Inner StackTrace: " + ex.InnerException.StackTrace);
                        Trace.WriteLine("Inner StackTrace: " + ex.InnerException.StackTrace);
                    }
                }

            }
            Trace.WriteLine("Risk rule run stopped");
            ReComputeTotals(data, output.ConvertAll(x => (IRuleScore)x));
            return output;
        }

        public static void ReComputeTotals(T data, IEnumerable<IRuleScore> rules)
        {
            ReComputeTotalsWithAccumulation(data, rules);
        }

        private static void ReComputeTotalsWithAccumulation(T data, IEnumerable<IRuleScore> rules)
        {
            // consolidate scores
            data.GlobalScore = 0;
            data.StaleObjectsScore = 0;
            data.PrivilegiedGroupScore = 0;
            data.TrustScore = 0;
            data.AnomalyScore = 0;
            data.MaturityLevel = 5;
            foreach (var rule in rules)
            {
                switch (rule.Category)
                {
                    case RiskRuleCategory.Anomalies:
                        data.AnomalyScore += rule.Points;
                        break;
                    case RiskRuleCategory.PrivilegedAccounts:
                        data.PrivilegiedGroupScore += rule.Points;
                        break;
                    case RiskRuleCategory.StaleObjects:
                        data.StaleObjectsScore += rule.Points;
                        break;
                    case RiskRuleCategory.Trusts:
                        data.TrustScore += rule.Points;
                        break;
                }
                var hcrule = RuleSet<T>.GetRuleFromID(rule.RiskId);
                if (hcrule != null)
                {
                    int level = hcrule.MaturityLevel;
                    if (level > 0 && level < data.MaturityLevel)
                        data.MaturityLevel = level;
                }
            }
            // limit to 100
            if (data.StaleObjectsScore > 100)
                data.StaleObjectsScore = 100;
            if (data.PrivilegiedGroupScore > 100)
                data.PrivilegiedGroupScore = 100;
            if (data.TrustScore > 100)
                data.TrustScore = 100;
            if (data.AnomalyScore > 100)
                data.AnomalyScore = 100;
            // max of all scores
            data.GlobalScore = Math.Max(data.StaleObjectsScore,
                                            Math.Max(data.PrivilegiedGroupScore,
                                            Math.Max(data.TrustScore, data.AnomalyScore)));
        }

        public static string GetRuleDescription(string ruleid)
        {
            if (_cachedRules == null || _cachedRules.Count == 0)
            {
                ReloadRules();
            }
            if (_cachedRules.ContainsKey(ruleid))
                return _cachedRules[ruleid].Title;
            return String.Empty;
        }

        public static RuleBase<T> GetRuleFromID(string ruleid)
        {
            if (_cachedRules == null || _cachedRules.Count == 0)
            {
                ReloadRules();
            }
            if (_cachedRules.ContainsKey(ruleid))
                return _cachedRules[ruleid];
            return null;

        }
        private void DisplaySupportMessage()
        {
            var license = LicenseCache.Instance.GetLicense();
            var isBasicLicense = license.IsBasic();
            if (isBasicLicense)
                Console.WriteLine("Please visit https://github.com/netwrix/pingcastle/issues to log an issue with the following details so the problem can be fixed");
            else
                Console.WriteLine("Please contact Netwrix support via the support portal (https://www.netwrix.com/support.html) with the following details so the problem can be fixed");

        }
    }
}
