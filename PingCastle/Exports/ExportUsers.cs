using PingCastle.ADWS;
using PingCastle.Healthcheck;
using System;
using System.Collections.Generic;
using System.IO;

namespace PingCastle.Exports
{
    public class ExportUsers : ExportBase
    {

        public override string Name
        {
            get { return "users"; }
        }

        public override string Description
        {
            get { return "Export all users"; }
        }


        public override void Export(string filename)
        {
            ADDomainInfo domainInfo = null;
            using (ADWebService adws = new ADWebService(Settings.Server, Settings.Port, Settings.Credential))
            {
                domainInfo = adws.DomainInfo;
                
                int export = 0;
                using (StreamWriter sw = File.CreateText(filename))
                {
                    var header = new List<string>();
                    var hcprop = AddData.GetProperties();
                    header.Add("DistinguishedName");
                    header.Add("sAMAccountName");
                    header.Add("scriptPath");
                    header.Add("primaryGroupID");
                    header.Add("lastLogonTimestamp");
                    header.Add("pwdLastSet");
                    header.Add("whenCreated");
                    header.Add("whenChanged");
                    header.Add("objectClass");
                    header.Add("userAccountControl");
                    header.AddRange(hcprop);
                    
                    sw.WriteLine(string.Join("\t", header.ToArray()));
                    
                    
                    WorkOnReturnedObjectByADWS callback =
                        (ADItem x) =>
                        {
                            var d = new AddData();
                            HealthcheckAnalyzer.ProcessAccountData(d, x, false, default(DateTime));
                            if ((++export % 500) == 0)
                            {
                                DisplayAdvancement("Exported: " + export);
                            }


                            var data = new List<string>();
                            data.Add(x.DistinguishedName);
                            data.Add(x.SAMAccountName);
                            data.Add(x.ScriptPath);
                            data.Add(x.PrimaryGroupID.ToString());
                            data.Add(x.LastLogonTimestamp.ToString("u"));
                            data.Add(x.PwdLastSet.ToString("u"));
                            data.Add(x.WhenCreated.ToString("u"));
                            data.Add(x.WhenChanged.ToString("u"));
                            data.Add(x.Class);
                            data.Add(x.UserAccountControl.ToString());
                            foreach (var p in hcprop)
                            {
                                data.Add(d.PropertiesSet.Contains(p).ToString());

                            }
                            sw.WriteLine(string.Join("\t", data.ToArray()));
                        };

                    DisplayAdvancement("Starting");
                    var properties = new List<string>(HealthcheckAnalyzer.userProperties);
                    properties.Add("whenChanged");
                    adws.Enumerate(domainInfo.DefaultNamingContext, HealthcheckAnalyzer.userFilter, properties.ToArray(), callback, "SubTree");
                    DisplayAdvancement("Done");
                }
            }
        }
    }
}
