//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Healthcheck;
using PingCastle.RPC;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;

namespace PingCastle.Scanners
{
    public class nullsessionTrustScanner : IScanner
    {

        public string Name { get { return "nullsession-trust"; } }
        public string Description { get { return "Dump the trusts of a domain via null session if possible"; } }

        RuntimeSettings Settings;

        public void Initialize(RuntimeSettings settings)
        {
            Settings = settings;
        }

        public DisplayState QueryForAdditionalParameterInInteractiveMode()
        {
            return Settings.EnsureDataCompleted("Server");
        }

        public void Export(string filename)
        {
            DisplayAdvancement("Starting");
            nrpc3 session = new nrpc3(); ;
            DisplayAdvancement("Trusts obtained via null session");
            List<TrustedDomain> domains;
            int res = session.DsrEnumerateDomainTrusts(Settings.Server, 0x3F, out domains);
            if (res != 0)
            {
                DisplayAdvancement("Error " + res + " (" + new Win32Exception(res).Message + ")");
                return;
            }
            DisplayAdvancement("Success - " + domains.Count + " trusts found");
            using (StreamWriter sw = File.CreateText(filename))
            {
                sw.WriteLine("Trust index,DnsDomainName,NetbiosDomainName,TrustAttributes,TrustType,Flags,DomainGuid,DomainSid,ParentIndex");
                int i = 0;
                foreach (var domain in domains)
                {
                    sw.WriteLine(i++ + "\t" + domain.DnsDomainName + "\t" + domain.NetbiosDomainName + "\t" +
                        TrustAnalyzer.GetTrustAttribute(domain.TrustAttributes) + " (" + domain.TrustAttributes + ")" + "\t" +
                        TrustAnalyzer.GetTrustType(domain.TrustType) + " (" + domain.TrustType + ")" + "\t" + domain.Flags + "\t" +
                        domain.DomainGuid + "\t" + domain.DomainSid + "\t" + domain.ParentIndex);
                }
            }
        }

        private static void DisplayAdvancement(string data)
        {
            string value = "[" + DateTime.Now.ToLongTimeString() + "] " + data;
            UserInterfaceFactory.GetUserInterface().DisplayMessage(value);
            Trace.WriteLine(value);
        }
    }
}
