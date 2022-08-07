using System;
using System.Configuration;

namespace PingCastle.Rules
{
    internal class CustomRulesSettings : ConfigurationSection
    {
        static CustomRulesSettings cachedSettings = null;
        public static CustomRulesSettings GetCustomRulesSettings()
        {
            if (cachedSettings == null)
                cachedSettings = ConfigurationManager.GetSection("customRulesSettings") as CustomRulesSettings;
            return cachedSettings;
        }

        [ConfigurationProperty("CustomRules", IsRequired = false)]
        public CustomRulesCollection CustomRules
        {
            get
            {
                return base["CustomRules"] as CustomRulesCollection;
            }
        }
    }

    [ConfigurationCollection(typeof(CustomRuleSettings), AddItemName = "CustomRule")]
    internal class CustomRulesCollection : ConfigurationElementCollection
    {
        public CustomRulesCollection()
        {

        }

        public CustomRuleSettings this[int index]
        {
            get { return (CustomRuleSettings)BaseGet(index); }
            set
            {
                if (BaseGet(index) != null)
                {
                    BaseRemoveAt(index);
                }
                BaseAdd(index, value);
            }
        }

        public void Add(CustomRuleSettings pluginConfig)
        {
            BaseAdd(pluginConfig);
        }

        public void Clear()
        {
            BaseClear();
        }

        protected override ConfigurationElement CreateNewElement()
        {
            return new CustomRuleSettings();
        }

        protected override object GetElementKey(ConfigurationElement element)
        {
            return ((CustomRuleSettings)element).RiskId;
        }

        public void Remove(CustomRuleSettings pluginConfig)
        {
            BaseRemove(pluginConfig.RiskId);
        }

        public void RemoveAt(int index)
        {
            BaseRemoveAt(index);
        }

        public void Remove(string name)
        {
            BaseRemove(name);
        }

    }

    public class CustomRuleSettings : ConfigurationElement
    {
        [ConfigurationProperty("RiskId", IsKey = true, IsRequired = true)]
        public string RiskId
        {
            get
            {
                return base["RiskId"] as string;
            }
            set
            {
                base["RiskId"] = value;
            }
        }

        [ConfigurationProperty("Computations")]
        public ComputationCollection Computations
        {
            get
            {
                return (ComputationCollection)base["Computations"];
            }
        }

        [ConfigurationProperty("MaturityLevel")]
        public int MaturityLevel
        {
            get
            {
                return (int) base["MaturityLevel"];
            }
            set
            {
                base["MaturityLevel"] = value;
            }
        }
    }

    [ConfigurationCollection(typeof(CustomRuleComputationSettings), AddItemName = "Computation", CollectionType = ConfigurationElementCollectionType.BasicMap)]
    public class ComputationCollection : ConfigurationElementCollection
    {
        public CustomRuleComputationSettings this[int index]
        {
            get { return (CustomRuleComputationSettings)BaseGet(index); }
            set
            {
                if (BaseGet(index) != null)
                {
                    BaseRemoveAt(index);
                }
                BaseAdd(index, value);
            }
        }

        public void Add(CustomRuleComputationSettings serviceConfig)
        {
            BaseAdd(serviceConfig);
        }

        public void Clear()
        {
            BaseClear();
        }

        protected override ConfigurationElement CreateNewElement()
        {
            return new CustomRuleComputationSettings();
        }

        protected override object GetElementKey(ConfigurationElement element)
        {
            return ((CustomRuleComputationSettings)element).Order;
        }

        public void Remove(CustomRuleComputationSettings serviceConfig)
        {
            BaseRemove(serviceConfig.Order);
        }

        public void RemoveAt(int index)
        {
            BaseRemoveAt(index);
        }

        public void Remove(String name)
        {
            BaseRemove(name);
        }

    }

    public class CustomRuleComputationSettings : ConfigurationElement
    {
        [ConfigurationProperty("Type", IsRequired = true)]
        public RuleComputationType Type
        {
            get
            {
                return (RuleComputationType) base["Type"];
            }
            set
            {
                base["Type"] = value;
            }
        }

        [ConfigurationProperty("Score", IsRequired = true)]
        public int Score
        {
            get
            {
                return (int)base["Score"];
            }
            set
            {
                base["Score"] = value;
            }
        }

        [ConfigurationProperty("Order", IsRequired = false, DefaultValue=1)]
        public int Order
        {
            get
            {
                return (int)base["Order"];
            }
            set
            {
                base["Order"] = value;
            }
        }

        [ConfigurationProperty("Threshold", IsRequired = false)]
        public int Threshold
        {
            get
            {
                return (int)base["Threshold"];
            }
            set
            {
                base["Threshold"] = value;
            }
        }

        public RuleComputationAttribute GetAttribute()
        {
            return new RuleComputationAttribute(Type, Score, Threshold, Order);
        }
    }
}
