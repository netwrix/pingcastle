//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace PingCastle.Scanners
{
    interface IScanner
    {
        void Initialize(string server, int port, NetworkCredential credential);
        void Export(string filename);
        string Name { get; }
		string Description { get; }
    }
}
