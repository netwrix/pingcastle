//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
// Contribution from woundride(https://github.com/woundride)

using PingCastle.UserInterface;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace PingCastle.Scanners
{

    public class RemoteScanner : ScannerBase
    {
        private readonly IUserInterface _ui = UserInterfaceFactory.GetUserInterface();

        public override string Name { get { return "remote"; } }
        public override string Description { get { return "Check if a remote desktop solution is installed on the computer."; } }

        static Dictionary<string, string> RemoteReference = new Dictionary<string, string>{

            {"AeroadminService" , "Aero Admin"},
            {"AnyDesk" , "AnyDesk"},
            {"AmmyyAdmin" , "Ammyy Admin"},
            {"BASupportExpressStandaloneService_Dameware" , "Dameware Remote Everywhere"},
            {"chromoting" , "Chrome Remote Desktop"},
            {"Client32" , "NetSupport Client"},
            {"DNTUS26" , "DameWare Remote Support 2.6"},
            {"dwmrcs" , "DameWare Mini Remote Control"},
            {"icas" , "iTALC"},
            {"LMIGuardianSvc" , "LogMeIn Rescue"},
            {"LogMeIn" , "LogMeIn"},
            {"Remote Administrator Service" , "Remote Administrator Service"},
            {"Remote Desktop Service" , "CloudBerry - MSP360"},
            {"RManService", "Remote Utilities"},
            {"sshd" , "OpenSSH SSH Server"},
            {"SupremoService" , "SupRemo"},
            {"SoftrosSpellChecker" , "Softros LAN Messenger"},
            {"SoftrosTSEngine" , "Softros LAN Messenger"},
            {"SplashtopRemoteService" , "Splashtop Remote Access"},
            {"TermService" , "Windows Remote Desktop Service"},
            {"TeamViewer" , "Team Viewer"},
            {"TeamViewer5" , "Team Viewer V5"},
            {"TigerVNC" , "Tiger VNC"},
            {"tvnserver" , "Tight VNC"},
            {"uvnc_service" , "Ultra VNC"},
            {"vncserver" , "Real VNC"},
            {"WebexService" , "Cisco WebEx"},
            {"Zoho Assist-Unattended Support" , "Zoho Assist"},
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
                _ui.Title = "Enter additional Service Name to check";
                _ui.Information = @"This scanner enumerate all well known services attributed to remote desktop solutions.
You can enter additional service to check. Enter them one by one and complete with an empty line.
Use the name provided in the service list. Example: Enter 'TeamViewer5' for the service 'TeamViewer version 5'.
Or just press enter to use the default.";
                input = _ui.AskForString();
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
            var names = new NativeMethods.UNICODE_STRING[RemoteReference.Count + customService.Count];
            try
            {
                int i = 0;
                foreach (var entry in RemoteReference)
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
                    foreach (var entry in RemoteReference)
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
    }
}
