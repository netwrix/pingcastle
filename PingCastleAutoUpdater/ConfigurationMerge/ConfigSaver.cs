namespace PingCastleAutoUpdater.ConfigurationMerge
{
    using System;
    using System.Xml;

    public class ConfigSaver : IConfigSaver
    {
        public void SaveConfig(XmlDocument config, string path)
        {
            if (config == null)
            {
                throw new ArgumentNullException(nameof(config));
            }

            if (path == null)
            {
                throw new ArgumentNullException(nameof(path));
            }

            try
            {
                config.Save(path);
            }
            catch (Exception ex)
            {
                throw new ConfigException($"Failed to save config file: {path}", ex);
            }
        }
    }
}