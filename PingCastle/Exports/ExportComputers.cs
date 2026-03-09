using PingCastle.ADWS;
using PingCastle.Healthcheck;
using PingCastle.misc;
using PingCastleCommon;
using System;
using System.Collections.Generic;
using System.IO;

namespace PingCastle.Exports
{
    public class ExportComputers : ExportBase
    {
        private IIdentityProvider _identityProvider;
        private IWindowsNativeMethods _nativeMethods;

        public override string Name => "computers";

        public override string Description => "Export all computers";

        public override void Export(string filename)
        {
            _identityProvider = _identityProvider ?? ServiceProviderAccessor.GetServiceSafe<IIdentityProvider>();
            _nativeMethods = _nativeMethods ?? ServiceProviderAccessor.GetServiceSafe<IWindowsNativeMethods>();

            ADDomainInfo domainInfo = null;
            using (ADWebService adws = new ADWebService(Settings.Server, Settings.Port, Settings.Credential, _identityProvider, _nativeMethods))
            {
                domainInfo = adws.DomainInfo;
                var lapsAnalyzer = new LAPSAnalyzer(adws);

                int export = 0;
                using (StreamWriter sw = File.CreateText(filename))
                {
                    var header = new List<string>
                    {
                        "DistinguishedName",
                        "sAMAccountName",
                        "scriptPath",
                        "primaryGroupID",
                        "lastLogonTimestamp",
                        "pwdLastSet",
                        "whenCreated",
                        "objectClass",
                        "userAccountControl",
                        "Active (6 Months)",
                        "OperatingSystem",
                        "OperatingSystemVersion",
                        "PC OS 1",
                        "PC OS 2",
                        "IsCluster",
                        "admpwdExpiration",
                        "msLAPSExpiration",
                        "LAPS",
                        "LAPSNew",
                        "LAPSBoth",
                        "LAPSActive",
                        "LAPSNewActive",
                        "LAPSBothActive"
                    };

                    sw.WriteLine(string.Join("\t", header));

                    WorkOnReturnedObjectByADWS callback = (ADItem x) =>
                    {
                        var d = new AddData();
                        HealthcheckAnalyzer.ProcessAccountData(d, x, true, default(DateTime));

                        var data = new List<string>
                        {
                            x.DistinguishedName,
                            x.SAMAccountName,
                            x.ScriptPath,
                            x.PrimaryGroupID.ToString(),
                            x.LastLogonTimestamp.ToString("u"),
                            x.PwdLastSet.ToString("u"),
                            x.WhenCreated.ToString("u"),
                            x.Class,
                            x.UserAccountControl.ToString(),
                            IsActiveInLast6Months(x) ? "True" : "False",
                            x.OperatingSystem,
                            x.OperatingSystemVersion,
                            !string.IsNullOrEmpty(x.OperatingSystem) ? OperatingSystemHelper.GetOperatingSystem(x.OperatingSystem) : string.Empty,
                            (x.OperatingSystem?.Contains("Windows") == true) ? PingCastle.Report.ReportBase.GetOSVersionString(new HealthcheckOSVersionData(x)) : string.Empty,
                            IsCluster(x).ToString(),
                            GetLAPSLegacyExpiration(x, lapsAnalyzer),
                            GetLAPSWindowsExpiration(x, lapsAnalyzer),
                            d.PropertiesSet.Contains("LAPS").ToString(),
                            d.PropertiesSet.Contains("LAPSNew").ToString(),
                            d.PropertiesSet.Contains("LAPSBoth").ToString(),
                            d.PropertiesSet.Contains("LAPSActive").ToString(),
                            d.PropertiesSet.Contains("LAPSNewActive").ToString(),
                            d.PropertiesSet.Contains("LAPSBothActive").ToString()
                        };

                        if ((++export % 500) == 0)
                        {
                            DisplayAdvancement("Exported: " + export);
                        }

                        sw.WriteLine(string.Join("\t", data));
                    };

                    DisplayAdvancement("Starting");
                    var attributes = new List<string>(HealthcheckAnalyzer.computerProperties);
                    attributes.Add("replPropertyMetaData");
                    adws.Enumerate(domainInfo.DefaultNamingContext, HealthcheckAnalyzer.computerfilter, attributes.ToArray(), callback, "SubTree");
                    DisplayAdvancement("Done");
                }
            }
        }

        private bool IsActiveInLast6Months(ADItem x)
        {
            var now = DateTime.UtcNow;
            return (now - x.LastLogonTimestamp).TotalDays <= 180 ||
                   (now - x.PwdLastSet).TotalDays <= 180 ||
                   (now - x.WhenCreated).TotalDays <= 180;
        }

        private bool IsCluster(ADItem x)
        {
            if (x.ServicePrincipalName != null)
            {
                foreach (var sp in x.ServicePrincipalName)
                {
                    if (sp.StartsWith("MSClusterVirtualServer/"))
                        return true;
                }
            }

            return false;
        }

        private string GetLAPSLegacyExpiration(ADItem x, LAPSAnalyzer lapsAnalyzer)
        {
            if (lapsAnalyzer.LegacyLAPSIntId != 0 && x.ReplPropertyMetaData != null && x.ReplPropertyMetaData.ContainsKey(lapsAnalyzer.LegacyLAPSIntId))
            {
                var dd = x.ReplPropertyMetaData[lapsAnalyzer.LegacyLAPSIntId];
                return dd.LastOriginatingChange.ToString("u");
            }

            return string.Empty;
        }

        private string GetLAPSWindowsExpiration(ADItem x, LAPSAnalyzer lapsAnalyzer)
        {
            if (lapsAnalyzer.MsLAPSIntId != 0 && x.ReplPropertyMetaData != null && x.ReplPropertyMetaData.ContainsKey(lapsAnalyzer.MsLAPSIntId))
            {
                var dd = x.ReplPropertyMetaData[lapsAnalyzer.MsLAPSIntId];
                return dd.LastOriginatingChange.ToString("u");
            }
            else if (lapsAnalyzer.MsLAPSEncryptedIntId != 0 && x.ReplPropertyMetaData != null && x.ReplPropertyMetaData.ContainsKey(lapsAnalyzer.MsLAPSEncryptedIntId))
            {
                var dd = x.ReplPropertyMetaData[lapsAnalyzer.MsLAPSEncryptedIntId];
                return dd.LastOriginatingChange.ToString("u");
            }
            return string.Empty;
        }
    }
}