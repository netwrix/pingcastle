using PingCastle.ADWS;
using PingCastle.Healthcheck;
using System;
using System.Collections.Generic;
using System.IO;

namespace PingCastle.Exports
{
    public class ExportComputers : ExportBase
    {

        public override string Name
        {
            get { return "computers"; }
        }

        public override string Description
        {
            get { return "Export all computers"; }
        }


        public override void Export(string filename)
        {
            ADDomainInfo domainInfo = null;
            using (ADWebService adws = new ADWebService(Settings.Server, Settings.Port, Settings.Credential))
            {
                domainInfo = adws.DomainInfo;

                var lapsAnalyzer = new LAPSAnalyzer(adws);

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
                    header.Add("objectClass");
                    header.Add("userAccountControl");
                    header.AddRange(hcprop);
                    header.Add("OperatingSystem");
                    header.Add("OperatingSystemVersion");
                    header.Add("PC OS 1");
                    header.Add("PC OS 2");
                    header.Add("IsCluster");
                    header.Add("LAPS last update (legacy LAPS)");
                    header.Add("LAPS last update (Ms LAPS)");

                    sw.WriteLine(string.Join("\t", header.ToArray()));


                    WorkOnReturnedObjectByADWS callback =
                        (ADItem x) =>
                        {
                            var d = new AddData();
                            HealthcheckAnalyzer.ProcessAccountData(d, x, false, default(DateTime));
                            if (lapsAnalyzer.LegacyLAPSIntId != 0 && x.ReplPropertyMetaData != null && x.ReplPropertyMetaData.ContainsKey(lapsAnalyzer.LegacyLAPSIntId))
                            {
                                d.AddWithoutDetail("LAPS");
                            }
                            if (lapsAnalyzer.MsLAPSIntId != 0 && x.ReplPropertyMetaData != null && x.ReplPropertyMetaData.ContainsKey(lapsAnalyzer.MsLAPSIntId))
                            {
                                d.AddWithoutDetail("LAPSNew");
                            }
                            else if (lapsAnalyzer.MsLAPSEncryptedIntId != 0 && x.ReplPropertyMetaData != null && x.ReplPropertyMetaData.ContainsKey(lapsAnalyzer.MsLAPSEncryptedIntId))
                            {
                                d.AddWithoutDetail("LAPSNew");
                            }

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
                            data.Add(x.Class);
                            data.Add(x.UserAccountControl.ToString());
                            foreach (var p in hcprop)
                            {
                                data.Add(d.PropertiesSet.Contains(p).ToString());
                            }
                            data.Add(x.OperatingSystem);
                            data.Add(x.OperatingSystemVersion);
                            if (!string.IsNullOrEmpty(x.OperatingSystem) && !string.IsNullOrEmpty(x.OperatingSystemVersion))
                            {
                                data.Add(HealthcheckAnalyzer.GetOperatingSystem(x.OperatingSystem));
                                if (x.OperatingSystem.Contains("Windows"))
                                {
                                    var osv = new HealthcheckOSVersionData(x);
                                    data.Add(PingCastle.Report.ReportBase.GetOSVersionString(osv));
                                }
                                else
                                {
                                    data.Add(string.Empty);
                                }
                            }
                            else
                            {
                                data.Add(string.Empty);
                                data.Add(string.Empty);
                            }
                            if (x.ServicePrincipalName != null)
                            {
                                bool isCluster = false;
                                if (x.ServicePrincipalName != null)
                                {
                                    foreach (var sp in x.ServicePrincipalName)
                                    {
                                        if (sp.StartsWith("MSClusterVirtualServer/"))
                                        {
                                            isCluster = true;
                                            break;
                                        }
                                    }
                                }
                                data.Add(isCluster.ToString());
                            }
                            else
                            {
                                data.Add(false.ToString());
                            }
                            if (lapsAnalyzer.LegacyLAPSIntId != 0 && x.ReplPropertyMetaData != null && x.ReplPropertyMetaData.ContainsKey(lapsAnalyzer.LegacyLAPSIntId))
                            {
                                var dd = x.ReplPropertyMetaData[lapsAnalyzer.LegacyLAPSIntId];
                                data.Add(dd.LastOriginatingChange.ToString("u"));
                            }
                            else
                            {
                                data.Add(string.Empty);
                            }
                            if (lapsAnalyzer.MsLAPSIntId != 0 && x.ReplPropertyMetaData != null && x.ReplPropertyMetaData.ContainsKey(lapsAnalyzer.MsLAPSIntId))
                            {
                                var dd = x.ReplPropertyMetaData[lapsAnalyzer.MsLAPSIntId];
                                data.Add(dd.LastOriginatingChange.ToString("u"));
                            }
                            else if (lapsAnalyzer.MsLAPSEncryptedIntId != 0 && x.ReplPropertyMetaData != null && x.ReplPropertyMetaData.ContainsKey(lapsAnalyzer.MsLAPSEncryptedIntId))
                            {
                                var dd = x.ReplPropertyMetaData[lapsAnalyzer.MsLAPSEncryptedIntId];
                                data.Add(dd.LastOriginatingChange.ToString("u"));
                            }
                            {
                                data.Add(string.Empty);
                            }
                            sw.WriteLine(string.Join("\t", data.ToArray()));
                        };

                    DisplayAdvancement("Starting");
                    var attributes = new List<string>(HealthcheckAnalyzer.computerProperties);
                    attributes.Add("replPropertyMetaData");
                    adws.Enumerate(domainInfo.DefaultNamingContext, HealthcheckAnalyzer.computerfilter, attributes.ToArray(), callback, "SubTree");
                    DisplayAdvancement("Done");
                }
            }
        }
    }
}
