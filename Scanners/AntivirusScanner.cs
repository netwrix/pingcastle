using PingCastle.UserInterface;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;

namespace PingCastle.Scanners
{
    public sealed class AntivirusScanner : ScannerBase
    {
        public override string Name { get { return "antivirus"; } }
        public override string Description { get { return "Check for computers without known antivirus installed. It is used to detect unprotected computers but may also report computers with unknown antivirus."; } }

        static Dictionary<string, string> AVReference = new Dictionary<string, string>{

            {"avast! Antivirus", "Avast"},
            {"aswBcc", "Avast"},
            {"Avast Business Console Client Antivirus Service", "Avast"},

            {"epag", "Bitdefender Endpoint Agent"},
            {"EPIntegrationService", "Bitdefender Endpoint Integration Service"},
            {"EPProtectedService", "Bitdefender Endpoint Protected Service"},
            {"epredline", "Bitdefender Endpoint Redline Services"},
            {"EPSecurityService", "Bitdefender Endpoint Security Service"},
            {"EPUpdateService", "Bitdefender Endpoint Update Service"},

            {"CiscoAMP", "Cisco Secure endpoint"},

            {"CSFalconService", "CrowdStrike Falcon Sensor Service"},

            {"CylanceSvc", "Cylance"},

            {"CynetLauncher", "Cynet Launcher Service"},

            {"ekm", "ESET"},
            {"epfw", "ESET"},
            {"epfwlwf", "ESET"},
            {"epfwwfp" , "ESET"},
            {"EraAgentSvc", "ESET"},

            {"xagt" , "FireEye Endpoint Agent"},

            {"fgprocsvc" , "ForeScout Remote Inspection Service"},
            {"SecureConnector" , "ForeScout SecureConnector Service"},

            {"fsdevcon", "F-Secure"},
            {"FSDFWD", "F-Secure"},
            {"F-Secure Network Request Broker", "F-Secure"},
            {"FSMA", "F-Secure"},
            {"FSORSPClient", "F-Secure"},

            {"klif", "Kasperksky"},
            {"klim", "Kasperksky"},
            {"kltdi", "Kasperksky"},
            {"kavfsslp", "Kasperksky"},
            {"KAVFSGT", "Kasperksky"},
            {"KAVFS", "Kasperksky"},

            {"enterceptagent", "MacAfee"},
            {"macmnsvc", "MacAfee Agent Common Services"},
            {"masvc", "MacAfee Agent Service"},
            {"McAfeeFramework", "MacAfee Agent Backwards Compatiblity Service"},
            {"McAfeeEngineService", "MacAfee"},
            {"mfefire", "MacAfee Firewall Core Service"},
            {"mfemms", "MacAfee Service Controller"},
            {"mfevtp", "MacAfee Validation Trust Protection Service"},
            {"mfewc", "MacAfee Endpoint Security Web Control Service"},

            {"cyverak", "PaloAlto Traps KernelDriver"},
            {"cyvrmtgn", "PaloAlto Traps KernelDriver"},
            {"cyvrfsfd", "PaloAlto Traps FileSystemDriver"},
            {"cyserver", "PaloAlto Traps Reporting Service"},
            {"CyveraService", "PaloAlto Traps"},
            {"tlaservice", "PaloAlto Traps Local Analysis Service"},
            {"twdservice", "PaloAlto Traps Watchdog Service"},

            {"SentinelAgent", "SentinelOne"},
            {"SentinelHelperService", "SentinelOne"},
            {"SentinelStaticEngine ", "SentinelIbe Static Service"},
            {"LogProcessorService ", "SentinelOne Agent Log Processing Service"},

            {"sophosssp", "Sophos"},
            {"Sophos Agent", "Sophos"},
            {"Sophos AutoUpdate Service", "Sophos"},
            {"Sophos Clean Service", "Sophos"},
            {"Sophos Device Control Service", "Sophos"},
            {"Sophos File Scanner Service", "Sophos"},
            {"Sophos Health Service", "Sophos"},
            {"Sophos MCS Agent", "Sophos"},
            {"Sophos MCS Client", "Sophos"},
            {"Sophos Message Router", "Sophos"},
            {"Sophos Safestore Service", "Sophos"},
            {"Sophos System Protection Service", "Sophos"},
            {"Sophos Web Control Service", "Sophos"},
            {"sophossps", "Sophos"},

            {"SepMasterService" , "Symantec Endpoint Protection"},
            {"SNAC" , "Symantec Network Access Control"},
            {"Symantec System Recovery" , "Symantec System Recovery"},
            {"Smcinst", "Symantec Connect"},
            {"SmcService", "Symantec Connect"},

            {"Sysmon", "Sysmon"},

            {"AMSP", "Trend"},
            {"tmcomm", "Trend"},
            {"tmactmon", "Trend"},
            {"tmevtmgr", "Trend"},
            {"ntrtscan", "Trend Micro Worry Free Business"},

            {"WRSVC", "Webroot"},

            {"WinDefend", "Windows Defender Antivirus Service"},
            {"Sense ", "Windows Defender Advanced Threat Protection Service"},
            {"WdNisSvc ", "Windows Defender Antivirus Network Inspection Service"},


        };

        private readonly List<string> _customService = new List<string>();

        override protected string GetCsvHeader()
        {
            return "Computer\tService Found\tDescription";
        }

        public override DisplayState QueryForAdditionalParameterInInteractiveMode()
        {
            // Load any custom service names from the command line settings
            if (!Settings.AntivirusCustomServiceNames.IsNullOrEmpty())
            {
                _customService.Clear();
                _customService.AddRange(Settings.AntivirusCustomServiceNames);
            }

            // For a batch scan we will need scanning mode to have been set
            if (ScanningMode != 0)
            {
                // Use default if the server is not set.
                Settings.Server ??= IPGlobalProperties.GetIPGlobalProperties().DomainName;
                // All other settings will have been set at the command line, so return.
                return DisplayState.Run;
            }

            var state = base.QueryForAdditionalParameterInInteractiveMode();
            if (state != DisplayState.Run)
                return state;

            // If we haven't got the list of custom services, ask the user.
            if (_customService.Count == 0)
            {
                IUserInterface userInterface = UserInterfaceFactory.GetUserInterface();
                do
                {
                    userInterface.Title = "Enter additional Service Name to check";
                    userInterface.Information = @"This scanner enumerate all well known services attributed to antivirus suppliers.
You can enter additional service to check. Enter them one by one and complete with an empty line.
Use the name provided in the service list. Example: Enter 'SepMasterService' for the service 'Symantec Endpoint Protection'.
Or just press enter to use the default.";

                    string input = userInterface.AskForString();
                    if (!string.IsNullOrEmpty(input))
                    {
                        if (!_customService.Contains(input))
                        {
                            _customService.Add(input);
                        }
                    }
                    else
                    {
                        break;
                    }
                } while (true);
            }
            return DisplayState.Run;
        }

        protected override string GetCsvData(string computer)
        {
            StringBuilder sb = new StringBuilder();
            NativeMethods.UNICODE_STRING us = new NativeMethods.UNICODE_STRING();
            NativeMethods.LSA_OBJECT_ATTRIBUTES loa = new NativeMethods.LSA_OBJECT_ATTRIBUTES();
            us.Initialize(computer);
            uint ret = NativeMethods.LsaOpenPolicy(ref us, ref loa, 0x00000800, out IntPtr policyHandle);
            us.Dispose();
            if (ret != 0)
            {
                Trace.WriteLine("LsaOpenPolicy 0x" + ret.ToString("x") + " for " + computer);
                sb.Append(computer);
                sb.Append("\tUnable to connect\tPingCastle couldn't connect to the computer. The error was 0x" + ret.ToString("x"));
                return sb.ToString();
            }
            var names = new NativeMethods.UNICODE_STRING[AVReference.Count + _customService.Count];
            try
            {
                PrepareNameList(names);

                // Make the call to translate all the names into SIDs
                ret = NativeMethods.LsaLookupNames(policyHandle, names.Length, names,
                    out IntPtr referencedDomains, out IntPtr sids);

                // Handle error codes
                if (ret == 0xC0000073) //STATUS_NONE_MAPPED
                {
                    sb.Append(computer);
                    sb.Append("\tNo known service found\tIf you think that the information is incorrect, please contact PingCastle support to add the antivirus in the checked list.");
                    return sb.ToString();
                }
                if (ret != 0 && ret != 0x00000107) // ignore STATUS_SOME_NOT_MAPPED
                {
                    Trace.WriteLine("LsaLookupNames 0x" + ret.ToString("x"));
                    sb.Append(computer);
                    sb.Append("\tUnable to lookup\tPingCastle couldn't translate the SID to the computer. The error was 0x" + ret.ToString("x"));
                    return sb.ToString();
                }

                try
                {
                    MarshalUnmananagedArray2Struct(sids, names.Length,
                        out NativeMethods.LSA_TRANSLATED_SID[] translated);

                    var avEntries = ProcessResultToList(computer, translated, sb);

                    OutputEntriesToTabDelimitedStringBuilder(sb, avEntries);
                }
                finally
                {
                    NativeMethods.LsaFreeMemory(referencedDomains);
                    NativeMethods.LsaFreeMemory(sids);
                }
            }
            finally
            {
                NativeMethods.LsaClose(policyHandle);
                for (int k = 0; k < names.Length; k++)
                {
                    names[k].Dispose();
                }
            }
            return sb.ToString();
        }

        private static void OutputEntriesToTabDelimitedStringBuilder(StringBuilder sb, List<AntivirusEntry> avEntries)
        {
           foreach(var entry in avEntries)
           {
               if (sb.Length != 0)
               {
                   sb.Append("\r\n");
               }
               sb.Append(entry.Computer);
               sb.Append("\t");
               sb.Append(entry.ServiceName);
               sb.Append("\t");
               sb.Append(entry.Description);
           }
        }

        private List<AntivirusEntry> ProcessResultToList(
            string computer,
            NativeMethods.LSA_TRANSLATED_SID[] translated,
            StringBuilder sb)
        {
            List<AntivirusEntry> antivirusEntries = new List<AntivirusEntry>();

            var i = 0;
            foreach (var entry in AVReference)
            {
                if (translated[i].DomainIndex >= 0)
                {
                    antivirusEntries.Add(new AntivirusEntry
                    {
                        Computer = computer,
                        ServiceName = entry.Key,
                        Description = entry.Value
                    });
                }
                i++;
            }
            foreach (var entry in _customService)
            {
                if (translated[i].DomainIndex >= 0)
                {
                    antivirusEntries.Add(new AntivirusEntry
                    {
                        Computer = computer,
                        ServiceName = entry,
                        Description = "Custom Search"
                    });
                }
                i++;
            }

            return antivirusEntries;
        }

        private void PrepareNameList(NativeMethods.UNICODE_STRING[] names)
        {
            int i = 0;
            foreach (var entry in AVReference)
            {
                names[i] = new NativeMethods.UNICODE_STRING();
                names[i].Initialize("NT Service\\" + entry.Key);
                i++;
            }
            foreach (var entry in _customService)
            {
                names[i] = new NativeMethods.UNICODE_STRING();
                names[i].Initialize("NT Service\\" + entry);
                i++;
            }
        }

        public static void MarshalUnmananagedArray2Struct<T>(IntPtr unmanagedArray, int length, out T[] mangagedArray)
        {
            var size = Marshal.SizeOf(typeof(T));
            mangagedArray = new T[length];

            for (int i = 0; i < length; i++)
            {
                IntPtr ins = new IntPtr(unmanagedArray.ToInt64() + i * size);
                mangagedArray[i] = (T)Marshal.PtrToStructure(ins, typeof(T));
            }
        }
    }

    public struct AntivirusEntry
    {
        public string Computer { get; set; }
        [DisplayName("Service Found")]
        public string  ServiceName { get; set; }
        public string Description { get; set; }
    }
}
