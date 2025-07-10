namespace PingCastleAutoUpdater.ConfigurationMerge
{
    using System.Xml.Linq;

    public interface IConfigSaver
    {
        void SaveConfig(XDocument config, string path);
    }
}