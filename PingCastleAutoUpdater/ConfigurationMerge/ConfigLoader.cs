namespace PingCastleAutoUpdater.ConfigurationMerge
{
    using System;
    using System.Xml.Linq;

    public class ConfigLoader : IConfigLoader
    {
        public XDocument LoadConfig(string path)
        {
            try
            {
                return XDocument.Load(path);
            }
            catch (Exception ex)
            {
                throw new ConfigException($"Failed to load config file: {path}", ex);
            }
        }
    }
}