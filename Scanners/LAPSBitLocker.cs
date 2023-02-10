using PingCastle.ADWS;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text.RegularExpressions;

namespace PingCastle.Scanners
{
    public class LAPSBitLocker : IScanner
    {

        public string Name { get { return "laps_bitlocker"; } }
        public string Description { get { return "Check on the AD if LAPS and/or BitLocker has been enabled for all computers on the domain."; } }

        RuntimeSettings Settings;

        public void Initialize(RuntimeSettings settings)
        {
            Settings = settings;
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

            using (ADWebService adws = new ADWebService(Settings.Server, Settings.Port, Settings.Credential))
            {
                domainInfo = adws.DomainInfo;

                var computers = new List<Computer>();

                DisplayAdvancement("Resolving LAPS attribute");

                var attributeAdmPwd = "ms-Mcs-AdmPwd";
                string[] propertiesLaps = new string[] { "name" };
                // note: the LDAP request does not contain ms-MCS-AdmPwd because in the old time, MS consultant was installing customized version of the attriute, * being replaced by the company name
                // check the oid instead ? (which was the same even if the attribute name was not)
                adws.Enumerate(domainInfo.SchemaNamingContext, "(name=ms-*-AdmPwd)", propertiesLaps, (ADItem aditem) => { attributeAdmPwd = aditem.Name; }, "OneLevel");
                DisplayAdvancement("LAPS attribute is " + attributeAdmPwd);
                DisplayAdvancement("Iterating through computer objects (all except disabled ones)");
                string[] properties = new string[] { "DistinguishedName", "dNSHostName", "msDS-ReplAttributeMetaData", "whenCreated", "lastLogonTimestamp", "operatingSystem" };

                WorkOnReturnedObjectByADWS callback =
                    (ADItem x) =>
                    {
                        var computer = new Computer()
                        {
                            DN = x.DistinguishedName,
                            DNS = x.DNSHostName,
                            WhenCreated = x.WhenCreated,
                            LastLogonTimestamp = x.LastLogonTimestamp,
                            OperatingSystem = x.OperatingSystem,
                        };
                        if (x.msDSReplAttributeMetaData.ContainsKey(attributeAdmPwd))
                        {
                            computer.HasLAPS = true;
                            computer.LAPSLastChange = x.msDSReplAttributeMetaData[attributeAdmPwd].LastOriginatingChange;
                        }
                        computers.Add(computer);
                    };

                adws.Enumerate(domainInfo.DefaultNamingContext, "(&(ObjectCategory=computer)(!userAccountControl:1.2.840.113556.1.4.803:=2))", properties, callback);
                DisplayAdvancement("Looking for BitLocker information");
                foreach (var computer in computers)
                {
                    WorkOnReturnedObjectByADWS callbackBitLocker =
                    (ADItem x) =>
                    {
                        const string re1 = "CN=" +
                            "([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\\\\\+|-)[0-9]{2}:[0-9]{2})\\{" +
                            "([A-Z0-9]{8}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{12})" +
                            "\\},";

                        Regex r = new Regex(re1, RegexOptions.IgnoreCase | RegexOptions.Singleline);
                        Match m = r.Match(x.DistinguishedName);
                        if (m.Success)
                        {
                            computer.HasBitLocker = true;
                            // + sign has to be escaped in LDAP
                            var date = DateTime.Parse(m.Groups[1].ToString().Replace("\\+", "+"));
                            if (computer.BitLockerLastChange < date)
                                computer.BitLockerLastChange = date;
                            //string guid = m.Groups[2].ToString();
                        }
                        else
                        {
                            Trace.WriteLine("Object found but didn't match the regex: " + x.DistinguishedName);
                        }
                        var d = x.DistinguishedName;
                    };
                    adws.Enumerate(computer.DN, "(objectClass=*)", null, callbackBitLocker, "OneLevel");
                }
                DisplayAdvancement("Writing to file");
                using (var sw = File.CreateText(filename))
                {
                    sw.WriteLine("DN\tDNS\tWhen Created\tLast Logon Timestamp\tOperating System\tHasLAPS\tLAPS changed date\tHasBitlocker\tBitlocker change date");
                    foreach (var computer in computers)
                    {
                        sw.WriteLine(computer.DN + "\t" + computer.DNS + "\t" + computer.WhenCreated.ToString("u") + "\t" + computer.LastLogonTimestamp.ToString("u") + "\t" + computer.OperatingSystem + "\t" + computer.HasLAPS + "\t" + (computer.HasLAPS ? computer.LAPSLastChange.ToString("u") : "") + "\t" + computer.HasBitLocker + "\t" + (computer.HasBitLocker ? computer.BitLockerLastChange.ToString("u") : ""));
                    }
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

        public DisplayState QueryForAdditionalParameterInInteractiveMode()
        {
            return Settings.EnsureDataCompleted("Server");
        }


    }
}
