//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.Security.Principal;

namespace PingCastle.Scanners
{
    public class localAdminsScanner : ScannerBase
    {

        public override string Name { get { return "localadmin"; } }
        public override string Description { get { return "Enumerate the local administrators of a computer."; } }

        override protected string GetCsvHeader()
        {
            return "Computer\tSID\tAccount";
        }

        override protected string GetCsvData(string computer)
        {
            string output = null;
            List<SecurityIdentifier> users = localAdminsEnumerator.Export(computer);

            foreach (SecurityIdentifier user in users)
            {
                string account = ConvertSIDToName(user.Value, computer);
                if (!String.IsNullOrEmpty(output))
                    output += "\r\n";
                output += computer + "\t" + user.Value + "\t" + account;
            }
            return output;
        }

        static string ConvertSIDToName(string sidstring, string server)
        {
            string referencedDomain = null;
            return NativeMethods.ConvertSIDToNameWithWindowsAPI(sidstring, server, out referencedDomain);
        }
    }
}
