using System.Collections.Generic;
using System.Configuration;

namespace PingCastle.Healthcheck
{
    public interface IInfrastructureSettings
    {
        ICollection<ISingleRiverbedSettings> Riverbeds { get; }
    }

    public interface ISingleRiverbedSettings
    {
        string samAccountName { get; }
    }

    internal class InfrastructureSettings : ConfigurationSection, IInfrastructureSettings
    {
        static InfrastructureSettings cachedSettings = null;
        public static InfrastructureSettings GetInfrastructureSettings()
        {
            if (cachedSettings == null)
                cachedSettings = ConfigurationManager.GetSection("infrastructureSettings") as InfrastructureSettings;
            return cachedSettings;
        }

        [ConfigurationProperty("Riverbeds", IsRequired = false)]
        internal RiverbedsCollection RiverbedsInternal
        {
            get
            {
                return base["Riverbeds"] as RiverbedsCollection;
            }
        }

        private ICollection<ISingleRiverbedSettings> _Riverbeds;
        public ICollection<ISingleRiverbedSettings> Riverbeds
        {
            get
            {
                if (_Riverbeds == null)
                {
                    var o = new List<ISingleRiverbedSettings>();
                    foreach (SingleRiverbedSettings t in RiverbedsInternal)
                    {
                        o.Add(t);
                    }
                    _Riverbeds = (ICollection<ISingleRiverbedSettings>)o;
                }
                return _Riverbeds;
            }
        }
    }

    [ConfigurationCollection(typeof(SingleRiverbedSettings), AddItemName = "Riverbed")]
    internal class RiverbedsCollection : ConfigurationElementCollection
    {
        public RiverbedsCollection()
        {

        }

        public SingleRiverbedSettings this[int index]
        {
            get { return (SingleRiverbedSettings)BaseGet(index); }
            set
            {
                if (BaseGet(index) != null)
                {
                    BaseRemoveAt(index);
                }
                BaseAdd(index, value);
            }
        }

        public void Add(SingleRiverbedSettings pluginConfig)
        {
            BaseAdd(pluginConfig);
        }

        public void Clear()
        {
            BaseClear();
        }

        protected override ConfigurationElement CreateNewElement()
        {
            return new SingleRiverbedSettings();
        }

        protected override object GetElementKey(ConfigurationElement element)
        {
            return ((SingleRiverbedSettings)element).samAccountName;
        }

        public void Remove(SingleRiverbedSettings pluginConfig)
        {
            BaseRemove(pluginConfig.samAccountName);
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

    public class SingleRiverbedSettings : ConfigurationElement, ISingleRiverbedSettings
    {
        [ConfigurationProperty("samAccountName", IsKey = true, IsRequired = true)]
        public string samAccountName
        {
            get
            {
                return base["samAccountName"] as string;
            }
            set
            {
                base["samAccountName"] = value;
            }
        }
    }
}
