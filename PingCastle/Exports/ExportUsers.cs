using PingCastle.ADWS;
using PingCastle.Healthcheck;
using PingCastleCommon;
using System;
using System.Collections.Generic;
using System.IO;

namespace PingCastle.Exports
{
    public class ExportUsers : ExportBase
    {
        private IIdentityProvider _identityProvider;
        private IWindowsNativeMethods _nativeMethods;

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
            _identityProvider = _identityProvider ?? ServiceProviderAccessor.GetServiceSafe<IIdentityProvider>();
            _nativeMethods = _nativeMethods ?? ServiceProviderAccessor.GetServiceSafe<IWindowsNativeMethods>();

            ADDomainInfo domainInfo = null;
            using (ADWebService adws = new ADWebService(Settings.Server, Settings.Port, Settings.Credential, _identityProvider, _nativeMethods))
            {
                domainInfo = adws.DomainInfo;
                
                int export = 0;
                using (StreamWriter sw = File.CreateText(filename))
                {
                    var header = new List<string>();
                    var hcprop = AddData.GetProperties();
                    // LAPS properties are computer-specific, exclude from user export
                    var lapsProperties = new HashSet<string>
                    {
                        "LAPS", "LAPSNew", "LAPSBoth",
                        "LAPSActive", "LAPSNewActive", "LAPSBothActive"
                    };
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
                    foreach (var prop in hcprop)
                    {
                        // Skip LAPS properties (computer-only)
                        if (lapsProperties.Contains(prop))
                            continue;

                        if (prop == "BadPrimaryGroup")
                        {
                            header.Add("BadPrimaryGroup (Active Users Only)");
                        }
                        else
                        {
                            header.Add(prop);
                        }
                    }

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
                                // Skip LAPS properties (computer-only)
                                if (lapsProperties.Contains(p))
                                {
                                    continue;
                                }

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
