//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;

namespace PingCastle.Scanners
{
    public class startupScanner : ScannerBase
    {

        public override string Name { get { return "startup"; } }
        public override string Description { get { return "Get the last startup date of a computer. Can be used to determine if latest patches have been applied."; } }

        override protected string GetCsvHeader()
        {
            return "Computer\tStartup";
        }

        override protected string GetCsvData(string computer)
        {
            DateTime startup = NativeMethods.GetStartupTime(computer);
            if (startup != DateTime.MinValue)
            {
                return computer + "\t" + startup.ToString("yyyy-MM-dd HH:mm:ss");
            }
            return null;
        }
    }
}
