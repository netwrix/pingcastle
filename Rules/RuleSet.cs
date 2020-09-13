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
        private static List<RuleBase<T>> _rules = null;

        public static List<RuleBase<T>> Rules
        {
            get
            {
                if (_rules == null)
                {
                    _rules = LoadRules();
                }
                return _rules;
            }
        }

        private static List<RuleBase<T>> LoadRules()
        {
            // important: to work with W2000, we cannot use GetType because it will instanciate .Net 3.0 class then load the missing assembly
            // the trick here is to check only the exported type and put as internal the class using .Net 3.0 functionalities
            var output = new List<RuleBase<T>>();
            foreach (Type type in Assembly.GetAssembly(typeof(RuleSet<T>)).GetExportedTypes())
            {
                if (type.IsSubclassOf(typeof(RuleBase<T>)) && !type.IsAbstract)
                {
                    try
                    {
                        output.Add((RuleBase<T>)Activator.CreateInstance(type));
                    }
                    catch (Exception)
                    {
                        Trace.WriteLine("Unable to instanciate the type " + type);
                        throw;
                    }
                }
            }
            output.Sort((RuleBase<T> a, RuleBase<T> b)
                    =>
                {
                    return string.Compare(a.RiskId, b.RiskId);
                }
            );
            return output;
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
                Trace.WriteLine("Rule: " + rule.GetType().ToString());
                ReInitRule(rule);
                if (rule.Analyze(data))
                {
                    Trace.WriteLine("  matched");
                    output.Add(rule);
                }
            }
            Trace.WriteLine("Risk rule run stopped");
            ReComputeTotals(data, output.ConvertAll(x => (IRuleScore)x));
            return output;
        }

        public static void ReComputeTotals(T data, IEnumerable<IRuleScore> rules)
        {
            if (typeof(T).IsAssignableFrom(typeof(IRiskEvaluationOnObjective)))
            {
                ReComputeTotalsWithObjective(data, rules);
            }
            else
            {
                ReComputeTotalsWithAccumulation(data, rules);
            }
        }

        private static void ReComputeTotalsWithObjective(T data, IEnumerable<IRuleScore> rules)
        {
            // consolidate scores
            data.GlobalScore = 0;
            data.StaleObjectsScore = 0;
            data.PrivilegiedGroupScore = 0;
            data.TrustScore = 0;
            data.AnomalyScore = 0;
            foreach (var rule in rules)
            {
                switch (rule.Category)
                {
                    case RiskRuleCategory.Anomalies:
                        if (rule.Points > data.AnomalyScore)
                            data.AnomalyScore = rule.Points;
                        break;
                    case RiskRuleCategory.PrivilegedAccounts:
                        if (rule.Points > data.PrivilegiedGroupScore)
                            data.PrivilegiedGroupScore = rule.Points;
                        break;
                    case RiskRuleCategory.StaleObjects:
                        if (rule.Points > data.StaleObjectsScore)
                            data.StaleObjectsScore = rule.Points;
                        break;
                    case RiskRuleCategory.Trusts:
                        if (rule.Points > data.TrustScore)
                            data.TrustScore = rule.Points;
                        break;
                }
            }
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
            foreach (var rule in Rules)
            {
                if (rule.RiskId == ruleid)
                {
                    return rule.Title;
                }
            }
            return string.Empty;
        }

        public static RuleBase<T> GetRuleFromID(string ruleid)
        {
            foreach (var rule in Rules)
            {
                if (rule.RiskId == ruleid)
                {
                    return rule;
                }
            }
            return null;
        }
    }
}