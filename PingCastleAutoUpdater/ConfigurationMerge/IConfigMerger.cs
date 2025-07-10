namespace PingCastleAutoUpdater.ConfigurationMerge
{
    using System.Xml.Linq;

    public interface IConfigMerger
    {
        XDocument MergeConfigs(XDocument target, XDocument source);
    }
}