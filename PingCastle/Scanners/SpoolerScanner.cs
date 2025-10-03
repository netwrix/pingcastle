//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.RPC;
using System;

namespace PingCastle.Scanners
{
    public class SpoolerScanner : ScannerBase
    {

        public override string Name { get { return "spooler"; } }
        public override string Description { get { return "Check if the spooler service is remotely active. The spooler can be abused to get computer tokens when unconstrained delegations are exploited."; } }

        override protected string GetCsvHeader()
        {
            return "Computer\tSpoolerActive";
        }

        override protected string GetCsvData(string computer)
        {
            string output = null;
            bool spoolerActive = CheckIfTheSpoolerIsActive(computer);


            output = computer + "\t" + spoolerActive;
            return output;
        }

        public static bool CheckIfTheSpoolerIsActive(string computer)
        {
            IntPtr hHandle = IntPtr.Zero;
            var test = new rprn();

            var devmodeContainer = new PingCastle.RPC.rprn.DEVMODE_CONTAINER();
            try
            {
                var ret = test.RpcOpenPrinter("\\\\" + computer, out hHandle, null, ref devmodeContainer, 0);
                if (ret == 0)
                {
                    return true;
                }
            }
            finally
            {
                if (hHandle != IntPtr.Zero)
                    test.RpcClosePrinter(ref hHandle);
            }
            return false;
        }
    }
}
