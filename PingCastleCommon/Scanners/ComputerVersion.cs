//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
namespace PingCastle.Scanners
{
    using Microsoft.Graph.Beta.Models;
    using PingCastle.ADWS;

    public class ComputerVersion : ScannerBase
    {
        private readonly IWindowsNativeMethods _nativeMethods;

        public ComputerVersion(IWindowsNativeMethods nativeMethods, IIdentityProvider identityProvider)
            :base(identityProvider)
        {
            _nativeMethods = nativeMethods;
        }

        public override string Name { get { return "computerversion"; } }

        public override string Description { get { return "Get the version of a computer. Can be used to determine if obsolete operating systems are still present."; } }

        override protected string GetCsvHeader()
        {
            return "Computer\tVersion";
        }

        override protected string GetCsvData(string computer, System.Threading.CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string version = _nativeMethods.GetComputerVersion(computer);
            if (version != "not found")
            {
                return computer + "\t" + version;
            }
            return null;
        }
    }
}
