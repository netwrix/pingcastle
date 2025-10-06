//
// Copyright (c) Vincent LE TOUX for Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Cloud.Common;

namespace PingCastle.Cloud.Tokens
{
    public class JwtPayload : JsonSerialization<JwtPayload>
    {
        public string aud { get; set; }
        public long exp { get; set; }
        public string iss { get; set; }


        public string jti { get; set; }
        public long nbf { get; set; }
        public string sub { get; set; }
        public long iat { get; set; }
    }
}
