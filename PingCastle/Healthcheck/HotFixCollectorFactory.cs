namespace PingCastle.Healthcheck;

using misc;

public static class HotFixCollectorFactory
{
    /// <summary>
    /// Creates a new instance of HotFixCollector with CIM as primary and WMI as fallback.
    /// </summary>
    /// <returns>A new HotFixCollector instance</returns>
    public static HotFixCollector Create()
    {
        return new HotFixCollector(new CimHotfixHelper(), new WmiHotfixHelper());
    }
}