//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.RPC;
using System;
using System.Diagnostics;
using System.Security.Principal;
using System.Text;

namespace PingCastle.Scanners
{
    public class NullSessionScanner : ScannerBase
    {

        public override string Name { get { return "nullsession"; } }
        public override string Description { get { return "Check if null sessions are enabled and provide example(s)."; } }

        public static int NullSessionEnumerationLimit = int.MaxValue;

        override protected string GetCsvHeader()
        {
            return "Computer\tIs Null sessions enabled\tExample";
        }

        override protected string GetCsvData(string computer)
        {
            StringBuilder sb = new StringBuilder();
            string header = null;
            NullSessionTester session = new NullSessionTester(Settings.Server,
                            (NTAccount server) =>
                            {
                                if (sb.Length != 0)
                                {
                                    sb.AppendLine();
                                }
                                sb.Append(header);
                                sb.Append(server.Value);
                            });
            bool enabled = false;
            DisplayAdvancement(computer, "Testing MS-SAMR");
            header = computer + " \tMS-SAMR\t";
            if (session.EnumerateAccount(TypeOfEnumeration.Samr, (ScanningMode == 0 ? 1 : NullSessionEnumerationLimit)))
            {
                DisplayAdvancement(computer, "Null session is enabled (at least MS-SAMR)");
                enabled = true;
            }
            else
            {
                DisplayAdvancement(computer, "MS-SAMR disabled");
            }
            if (!enabled)
            {
                DisplayAdvancement(computer, "Testing MS-LSAT");
                header = computer + "\tMS-LSAT\t";
                if (session.EnumerateAccount(TypeOfEnumeration.Lsa, (ScanningMode == 0 ? 1 : NullSessionEnumerationLimit)))
                {
                    DisplayAdvancement(computer, "Null session is enabled (only MS-LSAT)");
                    enabled = true;
                }
                else
                {
                    DisplayAdvancement(computer, "MS-LSAT disabled");
                }
            }
            if (!enabled)
            {
                DisplayAdvancement(computer, "Null session is disabled");
                sb.Append(computer);
                sb.Append("\tNone\t");
            }
            return sb.ToString();
        }

        private static void DisplayAdvancement(string computer, string data)
        {
            string value = "[" + DateTime.Now.ToLongTimeString() + "] " + data;
            if (ScanningMode == 1)
                UserInterfaceFactory.GetUserInterface().DisplayMessage(value);
            Trace.WriteLine(value);
        }
    }

}
