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
    using ADWS;

    public class localAdminsScanner : ScannerBase
    {
        private readonly IWindowsNativeMethods _nativeMethods;

        public localAdminsScanner(IWindowsNativeMethods nativeMethods, IIdentityProvider identityProvider)
        :base(identityProvider)
        {
            _nativeMethods = nativeMethods;
        }

        public override string Name { get { return "localadmin"; } }
        public override string Description { get { return "Enumerate the local administrators of a computer."; } }

        override protected string GetCsvHeader()
        {
            return "Computer\tSID\tAccount";
        }

        override protected string GetCsvData(string computer, System.Threading.CancellationToken cancellationToken = default)
        {
            string output = null;
            List<SecurityIdentifier> users = localAdminsEnumerator.Export(computer);

            foreach (SecurityIdentifier user in users)
            {
                cancellationToken.ThrowIfCancellationRequested();
                string account = ConvertSIDToName(user.Value, computer);
                if (!String.IsNullOrEmpty(output))
                    output += "\r\n";
                output += computer + "\t" + user.Value + "\t" + account;
            }
            return output;
        }

        private string ConvertSIDToName(string sidstring, string server)
        {
            string referencedDomain = null;
            return _nativeMethods.ConvertSIDToName(sidstring, server, out referencedDomain);
        }
    }
}
