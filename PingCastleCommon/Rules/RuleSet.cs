//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Healthcheck;
using PingCastle.UserInterface;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Threading;

namespace PingCastle.Rules
{
    public class RuleSet<T> where T : IRiskEvaluation
    {
        private static Dictionary<string, RuleBase<T>> _cachedRules = null;
        private static readonly object _lock = new object();
        private static Type[] _cachedRuleTypes;

        public IInfrastructureSettings InfrastructureSettings { get; set; }
        private readonly IUserInterface _ui = UserInterfaceFactory.GetUserInterface();

        public static IEnumerable<RuleBase<T>> Rules
        {
            get
            {
                if (_cachedRules == null || _cachedRules.Count == 0)
                {
                    lock(_lock)
                    {
                        if (_cachedRules == null || _cachedRules.Count == 0)
                        {
                            ReloadRules();
                        }
                    }
                }
                return _cachedRules.Values;
            }
        }

        public static void ReloadRules()
        {
            lock (_lock)
            {
                var rules = new Dictionary<string, RuleBase<T>>();
                LoadRules(rules);
                _cachedRules = rules;
            }
        }

        public static void LoadRules(Dictionary<string, RuleBase<T>> rules)
        {
            // NOTE: This method uses the ServiceProviderAccessor, which assumes the ServiceProvider to available at all times.
            //       This does not work when called from ASP.NET code where the ServiceProvider may be scoped.
            //       If needed from ASP.NET, use GetRulesFromDI below, to get instances (uncached).

            // important: to work with W2000, we cannot use GetType because it will instanciate .Net 3.0 class then load the missing assembly
            // the trick here is to check only the exported type and put as internal the class using .Net 3.0 functionalities
            foreach (Type type in Assembly.GetAssembly(typeof(RuleSet<T>)).GetExportedTypes())
            {
                if (!type.IsSubclassOf(typeof(RuleBase<T>)) || type.IsAbstract)
                {
                    continue;
                }

                // We *should* have all rules in DI, but just in case, we miss some, fall back to Activator
                try
                {
                    var rule = ServiceProviderAccessor.Current.GetService(type) as RuleBase<T>;
                    if (rule is not null)
                    {
                        rules[rule.RiskId] = rule;
                        continue;
                    }
                }
                catch (Exception ex)
                {
                    Trace.WriteLine($"Dependency Injection failed for {type.Name}");
                }

                try
                {
                    var rule = Activator.CreateInstance(type) as RuleBase<T>;
                    if (rule != null)
                    {
                        if (rules.ContainsKey(rule.RiskId))
                        {
                            Trace.WriteLine("Rule Error: Duplicate rule ID: " + rule.RiskId);
                        }

                        rules[rule.RiskId] = rule;
                    }
                }
                catch (MissingMethodException)
                {
                    // Skip rules that require DI
                    Trace.WriteLine($"Rule Info: Skipping {type.Name} (no parameterless constructor)");
                }
                catch (Exception ex)
                {
                    Trace.WriteLine($"Rule Error: Unable to instantiate {type.Name}: {ex.Message}");
                    throw;
                }
            }
        }

        // For Dependency Injection-constructed rules with a provided IServiceProvider
        public static IEnumerable<RuleBase<T>> GetRulesFromDI(IServiceProvider serviceProvider)
        {
            var rules = new Dictionary<string, RuleBase<T>>();
            foreach (Type type in GetRuleTypes())
            {
                RuleBase<T> rule = null;
                try
                {
                    // Try DI first
                    rule = serviceProvider.GetService(type) as RuleBase<T>;

                    // Fallback to parameterless constructor
                    if (rule is null)
                    {
                        rule = Activator.CreateInstance(type) as RuleBase<T>;
                    }
                    if (rule is not null)
                    {
                        // Overwrite if duplicate RiskId
                        rules[rule.RiskId] = rule;
                    }
                }
                catch (MissingMethodException)
                {
                    Trace.WriteLine($"Rule Info: Skipping {type.Name} (no parameterless constructor and not registered in DI)");
                }
                catch (Exception ex)
                {
                    Trace.WriteLine($"Rule Error: Unable to instantiate {type.Name}: {ex.Message}");
                    throw;
                }
            }

            return rules.Values;
        }

        private static Type[] GetRuleTypes()
        {
            if (_cachedRuleTypes == null)
            {
                lock (_lock)
                {
                    if (_cachedRuleTypes == null)
                    {
                        var ruleBaseType = typeof(RuleBase<T>);
                        _cachedRuleTypes = AppDomain.CurrentDomain.GetAssemblies()
                            .SelectMany(a =>
                            {
                                try
                                {
                                    return a.GetExportedTypes();
                                }
                                catch
                                { 
                                    return Array.Empty<Type>();
                                }
                            })
                            .Where(type => ruleBaseType.IsAssignableFrom(type) && !type.IsAbstract)
                            .ToArray();
                    }
                }
            }

            return _cachedRuleTypes;
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

                UserInterfaceFactory.GetUserInterface().DisplayMessage("An error occured while loading custom rules: " + ex.Message);
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

        public List<RuleBase<T>> ComputeRiskRules(T data, CancellationToken cancellationToken = default)
        {
            var output = new List<RuleBase<T>>();
            Trace.WriteLine("Begining to run risk rule");
            foreach (var rule in Rules)
            {
                cancellationToken.ThrowIfCancellationRequested();
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
                    _ui.DisplayError("An exception occured when running the rule : " + ruleName);
                    Trace.WriteLine("An exception occured when running the rule : " + ruleName);
                    var supportService = ServiceProviderAccessor.GetServiceSafe<IDisplaySupportMessageService>();
                    if (supportService != null)
                    {
                        supportService.DisplaySupportMessage();
                    }
                    _ui.DisplayMessage("Message: " + ex.Message);
                    Trace.WriteLine("Message: " + ex.Message);
                    _ui.DisplayStackTrace("StackTrace: " + ex.StackTrace);
                    Trace.WriteLine("StackTrace: " + ex.StackTrace);
                    if (ex.InnerException != null)
                    {
                        _ui.DisplayStackTrace("Inner StackTrace: " + ex.InnerException.StackTrace);
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
    }
}
