using PingCastle.ADWS;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Text;

namespace PingCastle.Exports
{
    public abstract class ExportBase : IExport
    {
        protected NetworkCredential Credential { get; set; }

        protected int Port { get; set; }

        protected string Server { get; set; }

        public abstract string Name { get; }
        public abstract string Description { get; }

        public void Initialize(string server, int port, NetworkCredential credential)
        {
            Server = server;
            Port = port;
            Credential = credential;
        }



        public abstract void Export(string filename);

        protected static void DisplayAdvancement(string data)
        {
            string value = "[" + DateTime.Now.ToLongTimeString() + "] " + data;
            Console.WriteLine(value);
            Trace.WriteLine(value);
        }

        protected class AddData : PingCastle.Healthcheck.IAddAccountData
        {
            public static List<string> GetProperties()
            {
                var output = new List<string>();
                var ps = typeof(PingCastle.Healthcheck.HealthcheckAccountData).GetProperties();
                foreach (var p in ps)
                {
                    if (p.Name.StartsWith("Number"))
                    {
                        output.Add(p.Name.Substring("Number".Length));
                    }
                }
                return output;
            }

            public List<string> PropertiesSet = new List<string>();

            public void AddWithoutDetail(string property)
            {
                if (string.IsNullOrEmpty(property))
                    return;
                PropertiesSet.Add(property);
            }

            public void AddDetail(string property, Healthcheck.HealthcheckAccountDetailData data)
            {
                AddWithoutDetail(property);
            }

            public void AddSIDHistoryDetail(Healthcheck.HealthcheckAccountDetailData item, ADItem x)
            {
                AddWithoutDetail("SidHistory");
            }
        }
    }
}
