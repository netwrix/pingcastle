using PingCastle.Cloud.MsGraph;
using System.Diagnostics;

namespace PingCastle.misc
{
    public class Logging
    {
        public static void EnableLogFile()
        {
            Trace.AutoFlush = true;
            TextWriterTraceListener listener = new TextWriterTraceListener("trace.log");
            Trace.Listeners.Add(listener);
            var sazGenerator = new PingCastle.Cloud.Logs.SazGenerator();
            PingCastle.Cloud.Common.HttpClientHelper.EnableLoging(sazGenerator);
            GraphServiceClientFactory.SazGenerator = sazGenerator;
        }

    }
}