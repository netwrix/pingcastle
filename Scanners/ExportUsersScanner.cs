using PingCastle.ADWS;
using System;
using System.Diagnostics;
using System.IO;
using System.Net;

namespace PingCastle.Scanners
{
    public class ExportUsersScanner : IScanner
    {
        public string Name { get { return "export_user"; } }
        public string Description { get { return "Export all users of the AD with their creation date, last logon and last password change."; } }

        public string Server { get; private set; }
        public int Port { get; private set; }
        public NetworkCredential Credential { get; private set; }

        public void Initialize(string server, int port, NetworkCredential credential)
        {
            Server = server;
            Port = port;
            Credential = credential;
        }

        private class Computer
        {
            public string DN { get; set; }
            public string DNS { get; set; }
            public DateTime WhenCreated { get; set; }
            public DateTime LastLogonTimestamp { get; set; }
            public string OperatingSystem { get; set; }
            public bool HasLAPS { get; set; }
            public DateTime LAPSLastChange { get; set; }
            public bool HasBitLocker { get; set; }
            public DateTime BitLockerLastChange { get; set; }
        }

        public void Export(string filename)
        {
            ADDomainInfo domainInfo = null;

            using (ADWebService adws = new ADWebService(Server, Port, Credential))
            {
                domainInfo = adws.DomainInfo;

                DisplayAdvancement("Iterating through user objects (all except disabled ones)");
                string[] properties = new string[] { "DistinguishedName", "sAMAccountName", "userAccountControl", "whenCreated", "lastLogonTimestamp" };

                using (var sw = File.CreateText(filename))
                {
                    sw.WriteLine("SAMAccountName\tDN\tWhen Created\tLast Logon Timestamp");

                    WorkOnReturnedObjectByADWS callback =
                        (ADItem x) =>
                        {
                            sw.WriteLine(x.SAMAccountName + "\t" + x.DistinguishedName + "\t" + x.WhenCreated.ToString("u") + "\t" + x.LastLogonTimestamp.ToString("u") + "\t" + x.PwdLastSet.ToString("u"));
                        };
                    adws.Enumerate(domainInfo.DefaultNamingContext, "(&(objectClass=user)(objectCategory=person)(admincount=1)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(sAMAccountName=krbtgt)))", properties, callback);
                }

                DisplayAdvancement("Done");
            }
        }

        private static void DisplayAdvancement(string data)
        {
            string value = "[" + DateTime.Now.ToLongTimeString() + "] " + data;
            Console.WriteLine(value);
            Trace.WriteLine(value);
        }

        public bool QueryForAdditionalParameterInInteractiveMode()
        {
            return true;
        }
    }
}