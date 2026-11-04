using System;
using System.Collections.Generic;
using Microsoft.Extensions.Options;

namespace PingCastle.Healthcheck
{
    using PingCastleCommon.Options;

    public interface IInfrastructureSettings
    {
        ICollection<ISingleRiverbedSettings> Riverbeds { get; }
    }

    public interface ISingleRiverbedSettings
    {
        string SamAccountName { get; set; }
    }

    public class InfrastructureSettings : IInfrastructureSettings
    {
        static InfrastructureSettings cachedSettings = null;
        public static InfrastructureSettings GetInfrastructureSettings()
        {
            if (cachedSettings == null)
            {
                if (ServiceProviderAccessor.IsInitialized)
                {
                    var options = ServiceProviderAccessor.Current.GetService(typeof(IOptions<InfrastructureOptions>)) as IOptions<InfrastructureOptions>;
                    cachedSettings = new InfrastructureSettings();
                    if (options?.Value != null)
                    {
                        cachedSettings._riverbedsCollection = new List<SingleRiverbedSettings>();
                        foreach (var rbOption in options.Value.Riverbeds)
                        {
                            var rbSetting = new SingleRiverbedSettings();
                            rbSetting.SamAccountName = rbOption.SamAccountName;
                            cachedSettings._riverbedsCollection.Add(rbSetting);
                        }
                    }
                }
                else
                {
                    throw new ApplicationException("Could not load infrastructure options. Please check the appsettings.json file.");
                }
            }

            return cachedSettings;
        }

        private List<SingleRiverbedSettings> _riverbedsCollection = null;

        internal List<SingleRiverbedSettings> RiverbedsInternal => _riverbedsCollection;

        private ICollection<ISingleRiverbedSettings> _Riverbeds;
        public ICollection<ISingleRiverbedSettings> Riverbeds
        {
            get
            {
                if (_Riverbeds == null)
                {
                    var riverbtedSettings = new List<ISingleRiverbedSettings>();
                    foreach (SingleRiverbedSettings t in RiverbedsInternal)
                    {
                        riverbtedSettings.Add(t);
                    }

                    _Riverbeds = riverbtedSettings;
                }

                return _Riverbeds;
            }
        }
    }

    public class SingleRiverbedSettings : ISingleRiverbedSettings
    {
        public string SamAccountName { get; set; }
    }
}
