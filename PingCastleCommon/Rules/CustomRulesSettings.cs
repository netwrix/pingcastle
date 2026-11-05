namespace PingCastle.Rules
{
    using System;
    using System.Collections.Generic;
    using Microsoft.Extensions.Options;
    using PingCastleCommon.Options;

    internal class CustomRulesSettings
    {
        static CustomRulesSettings cachedSettings = null;
        public static CustomRulesSettings GetCustomRulesSettings()
        {
            if (cachedSettings == null)
            {
                if (ServiceProviderAccessor.IsInitialized)
                {
                    var options = ServiceProviderAccessor.Current.GetService(typeof(IOptions<CustomRulesOptions>)) as IOptions<CustomRulesOptions>;
                    cachedSettings = new CustomRulesSettings();
                    if (options?.Value != null)
                    {
                        cachedSettings._customRulesCollection = new List<CustomRuleSettings>();
                        foreach (var ruleOption in options.Value.CustomRules)
                        {
                            var ruleSetting = new CustomRuleSettings();
                            ruleSetting.RiskId = ruleOption.RiskId;
                            if (ruleOption.MaturityLevel.HasValue)
                            {
                                ruleSetting.MaturityLevel = ruleOption.MaturityLevel.Value;
                            }

                            var compCollection = new ComputationCollection();
                            foreach (var compOption in ruleOption.Computations)
                            {
                                var compSetting = new CustomRuleComputationSettings();
                                if (Enum.TryParse<RuleComputationType>(compOption.Type, out var computationType))
                                {
                                    compSetting.Type = computationType;
                                }

                                compSetting.Score = compOption.Score;
                                compSetting.Order = compOption.Order;
                                if (compOption.Threshold.HasValue)
                                {
                                    compSetting.Threshold = compOption.Threshold.Value;
                                }

                                compCollection.Add(compSetting);
                            }

                            ruleSetting.ComputationsInternal = compCollection;
                            cachedSettings._customRulesCollection.Add(ruleSetting);
                        }
                    }
                }
                else
                {
                    throw new ApplicationException("Could not configure Custom Rules options.");
                }
            }

            return cachedSettings;
        }

        private List<CustomRuleSettings> _customRulesCollection = null;

        public List<CustomRuleSettings> CustomRules => _customRulesCollection;
    }

    public class CustomRuleSettings
    {
        private ComputationCollection _computationsInternal = null;

        public string RiskId { get; set; }

        public ComputationCollection Computations => _computationsInternal;

        internal ComputationCollection ComputationsInternal
        {
            set => _computationsInternal = value;
        }

        public int MaturityLevel
        {
            get; set;
        }
    }

    public class ComputationCollection : List<CustomRuleComputationSettings>
    {
    }

    public class CustomRuleComputationSettings
    {
        public RuleComputationType Type
        {
            get; set;
        }

        public int Score
        {
            get; set;
        }

        public int Order
        {
            get; set;
        }

        public int Threshold
        {
            get; set;
        }

        public RuleComputationAttribute GetAttribute() => new(Type, Score, Threshold, Order);
    }
}
