//
// Copyright (c) Vincent LE TOUX for Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PingCastle.Cloud
{
    class PingCastleCloudException : Exception
    {
        public PingCastleCloudException(string message)
            : base(message)
        {
        }
    }
}
