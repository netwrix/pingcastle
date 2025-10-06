//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Diagnostics;
using System.Text;

namespace PingCastle.Scanners
{
    public class Smb3QueryNetworkScanner : ScannerBase
    {

        public override string Name { get { return "smb3querynetwork"; } }
        public override string Description { get { return "List all IP of the computer and the interface speed using SMB3. Authentication required. Used to find other networks such as the one used for administration."; } }

        override protected string GetCsvHeader()
        {
            return "Computer\tInterfaceId\tIP\tSpeed (in bit/s)";
        }

        override protected string GetCsvData(string computer)
        {
            StringBuilder sb = new StringBuilder();
            DisplayAdvancement(computer, "Connecting to SMB3");

            var o = Smb2ProtocolTest.GetFCTL_QUERY_NETWORK_INFO(computer, Settings.Credential);
            if (o == null)
            {
                sb.Append(computer);
                sb.Append("\t");
                sb.Append("Unable to retrive the information");
            }
            else
            {
                foreach (var info in o)
                {
                    if (sb.Length != 0)
                        sb.Append("\r\n");
                    sb.Append(computer);
                    sb.Append("\t");
                    sb.Append(info.Index);
                    sb.Append("\t");
                    sb.Append(info.IP);
                    sb.Append("\t");
                    sb.Append(info.LinkSpeed);
                }
            }
            return sb.ToString();
        }

        private static void DisplayAdvancement(string computer, string data)
        {
            string value = "[" + DateTime.Now.ToLongTimeString() + "] " + data;
            if (ScanningMode == 1)
                UserInterfaceFactory.GetUserInterface().DisplayError(value);
            Trace.WriteLine(value);
        }
    }

}
