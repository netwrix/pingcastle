namespace PingCastleAutoUpdater.ConfigurationMerge
{
    using System.Xml.Linq;

    public interface IConfigLoader
    {
        XDocument LoadConfig(string path);
    }
}