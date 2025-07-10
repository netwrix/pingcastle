//
// Copyright (c) Vincent LE TOUX for Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Cloud.Common;
using System.Collections.Generic;

namespace PingCastle.Cloud.Tokens
{
    public class JwtToken : JsonSerialization<JwtToken>
    {
        
        public string request_nonce { get; set; }
        
        public string refresh_token { get; set; }
        
        public string aud { get; set; }
        
        public string iss { get; set; }
        
        public long iat { get; set; }
        
        public long nbf { get; set; }
        
        public long exp { get; set; }
        
        public string act { get; set; }
        
        public string aio { get; set; }
        
        public List<string> amr { get; set; }
        
        public string appid { get; set; }
        
        public string appidacr { get; set; }
        
        public string deviceid { get; set; }
        
        public string family_name { get; set; }
        
        public string given_name { get; set; }
        
        public string ipaddr { get; set; }
        
        public string name { get; set; }
        
        public string oid { get; set; }
        
        public string onprem_sid { get; set; }
        
        public string puid { get; set; }
        
        public string rh { get; set; }
        
        public string scp { get; set; }
        
        public string sub { get; set; }
        
        public string tenant_region_scope { get; set; }
        
        public string tid { get; set; }
        
        public string unique_name { get; set; }
        
        public string upn { get; set; }
        
        public string uti { get; set; }
        
        public string ver { get; set; }

    }
}
