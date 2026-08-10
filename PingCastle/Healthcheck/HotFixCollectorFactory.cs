namespace PingCastle.Healthcheck;

using misc;

public static class HotFixCollectorFactory
{
    public static HotFixCollector Create()
    {
        return new HotFixCollector(new WmiHotfixHelper());
    }
}
