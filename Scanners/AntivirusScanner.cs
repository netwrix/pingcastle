using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace PingCastle.Scanners
{
    public class AntivirusScanner : ScannerBase
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

        static List<string> customService = new List<string>();

        override protected string GetCsvHeader()
        {
            return "Computer\tService Found\tDescription";
        }

        public override DisplayState QueryForAdditionalParameterInInteractiveMode()
        {
            var state = base.QueryForAdditionalParameterInInteractiveMode();
            if (state != DisplayState.Run)
                return state;

            string input = null;
            customService.Clear();
            do
            {
                ConsoleMenu.Title = "Enter additional Service Name to check";
                ConsoleMenu.Information = @"This scanner enumerate all well known services attributed to antivirus suppliers.
You can enter additional service to check. Enter them one by one and complete with an empty line.
Use the name provided in the service list. Example: Enter 'SepMasterService' for the service 'Symantec Endpoint Protection'.
Or just press enter to use the default.";
                input = ConsoleMenu.AskForString();
                if (!String.IsNullOrEmpty(input))
                {
                    if (!customService.Contains(input))
                    {
                        customService.Add(input);
                    }
                }
                else
                {
                    break;
                }
            } while (true);
            return DisplayState.Run;
        }

        protected override string GetCsvData(string computer)
        {
            StringBuilder sb = new StringBuilder();
            NativeMethods.UNICODE_STRING us = new NativeMethods.UNICODE_STRING();
            NativeMethods.LSA_OBJECT_ATTRIBUTES loa = new NativeMethods.LSA_OBJECT_ATTRIBUTES();
            us.Initialize(computer);
            IntPtr PolicyHandle = IntPtr.Zero;
            uint ret = NativeMethods.LsaOpenPolicy(ref us, ref loa, 0x00000800, out PolicyHandle);
            us.Dispose();
            if (ret != 0)
            {
                Trace.WriteLine("LsaOpenPolicy 0x" + ret.ToString("x") + " for " + computer);
                sb.Append(computer);
                sb.Append("\tUnable to connect\tPingCastle couldn't connect to the computer. The error was 0x" + ret.ToString("x"));
                return sb.ToString();
            }
            var names = new NativeMethods.UNICODE_STRING[AVReference.Count + customService.Count];
            try
            {
                int i = 0;
                foreach (var entry in AVReference)
                {
                    names[i] = new NativeMethods.UNICODE_STRING();
                    names[i].Initialize("NT Service\\" + entry.Key);
                    i++;
                }
                foreach (var entry in customService)
                {
                    names[i] = new NativeMethods.UNICODE_STRING();
                    names[i].Initialize("NT Service\\" + entry);
                    i++;
                }
                IntPtr ReferencedDomains, Sids;
                ret = NativeMethods.LsaLookupNames(PolicyHandle, names.Length, names, out ReferencedDomains, out Sids);
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
                    var domainList = (NativeMethods.LSA_REFERENCED_DOMAIN_LIST)Marshal.PtrToStructure(ReferencedDomains, typeof(NativeMethods.LSA_REFERENCED_DOMAIN_LIST));
                    if (domainList.Entries > 0)
                    {
                        var trustInfo = (NativeMethods.LSA_TRUST_INFORMATION)Marshal.PtrToStructure(domainList.Domains, typeof(NativeMethods.LSA_TRUST_INFORMATION));
                    }
                    NativeMethods.LSA_TRANSLATED_SID[] translated;
                    MarshalUnmananagedArray2Struct<NativeMethods.LSA_TRANSLATED_SID>(Sids, names.Length, out translated);

                    i = 0;
                    foreach (var entry in AVReference)
                    {
                        if (translated[i].DomainIndex >= 0)
                        {
                            if (sb.Length != 0)
                            {
                                sb.Append("\r\n");
                            }
                            sb.Append(computer);
                            sb.Append("\t");
                            sb.Append(entry.Key);
                            sb.Append("\t");
                            sb.Append(entry.Value);
                        }
                        i++;
                    }
                    foreach (var entry in customService)
                    {
                        if (sb.Length != 0)
                        {
                            sb.Append("\r\n");
                        }
                        sb.Append(computer);
                        sb.Append("\t");
                        sb.Append(entry);
                        sb.Append("\t");
                        sb.Append("Custom search");
                        i++;
                    }
                }
                finally
                {
                    NativeMethods.LsaFreeMemory(ReferencedDomains);
                    NativeMethods.LsaFreeMemory(Sids);
                }
            }
            finally
            {
                NativeMethods.LsaClose(PolicyHandle);
                for (int k = 0; k < names.Length; k++)
                {
                    names[k].Dispose();
                }
            }
            return sb.ToString();
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

        private static void DisplayAdvancement(string computer, string data)
        {
            string value = "[" + DateTime.Now.ToLongTimeString() + "] " + data;
            if (ScanningMode == 1)
                Console.WriteLine(value);
            Trace.WriteLine(value);
        }
    }
}
