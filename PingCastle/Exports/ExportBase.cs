using PingCastle.ADWS;
using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace PingCastle.Exports
{
    public abstract class ExportBase : IExport
    {
        public abstract string Name { get; }
        public abstract string Description { get; }

        protected RuntimeSettings Settings;

        public void Initialize(RuntimeSettings initialisationSettings)
        {
            Settings = initialisationSettings;
        }

        public DisplayState QueryForAdditionalParameterInInteractiveMode()
        {
            return Settings.EnsureDataCompleted("Server");
        }

        public abstract void Export(string filename);

        protected static void DisplayAdvancement(string data)
        {
            string value = "[" + DateTime.Now.ToLongTimeString() + "] " + data;
            UserInterfaceFactory.GetUserInterface().DisplayMessage(value);
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
                        var p2 = p.Name.Substring("Number".Length);
                        if (!string.IsNullOrEmpty(p2))
                            output.Add(p2);
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
