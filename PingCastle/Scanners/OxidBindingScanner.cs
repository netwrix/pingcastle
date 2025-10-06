//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.RPC;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace PingCastle.Scanners
{
    public class OxidBindingScanner : ScannerBase
    {

        public override string Name { get { return "oxidbindings"; } }
        public override string Description { get { return "List all IP of the computer via the Oxid Resolver (part of DCOM). No authentication. Used to find other networks such as the one used for administration."; } }

        override protected string GetCsvHeader()
        {
            return "Computer\tBinding";
        }

        override protected string GetCsvData(string computer)
        {
            StringBuilder sb = new StringBuilder();
            DisplayAdvancement(computer, "Connecting to Oxid Resolver");
            List<string> bindings;
            var oxid = new OxidBindings();
            int res = oxid.ServerAlive2(computer, out bindings);
            if (res != 0)
            {
                DisplayAdvancement(computer, "error " + res);
                sb.Append(computer);
                sb.Append("\tError " + res);
            }
            else
            {
                foreach (var binding in bindings)
                {
                    if (sb.Length != 0)
                        sb.Append("\r\n");
                    sb.Append(computer);
                    sb.Append("\t");
                    sb.Append(binding);
                }
            }
            return sb.ToString();
        }

        private static void DisplayAdvancement(string computer, string data)
        {
            string value = "[" + DateTime.Now.ToLongTimeString() + "] " + data;
            if (ScanningMode == 1)
            {
                UserInterfaceFactory.GetUserInterface().DisplayMessage(value);
            }
            Trace.WriteLine(value);
        }
    }

}
