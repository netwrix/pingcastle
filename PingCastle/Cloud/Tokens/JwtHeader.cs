//
// Copyright (c) Vincent LE TOUX for Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Cloud.Common;

namespace PingCastle.Cloud.Tokens
{
    public class JwtHeader : JsonSerialization<JwtHeader>
    {
        public string alg { get; set; }
        public string typ { get; set; }
        public string x5t { get; set; }
    }
}
