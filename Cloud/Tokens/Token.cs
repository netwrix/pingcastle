//
// Copyright (c) Vincent LE TOUX for Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Cloud.Common;

namespace PingCastle.Cloud.Tokens
{
    public class Token : JsonSerialization<Token>
    {
        
        public string token_type { get; set; }
        
        public string scope { get; set; }
        
        public uint expires_in { get; set; }
        
        public uint ext_expires_in { get; set; }
        
        public uint expires_on { get; set; }
        
        public uint not_before { get; set; }

        
        public string resource { get; set; }
        
        public string access_token { get; set; }
        
        public string refresh_token { get; set; }
        
        public string id_token { get; set; }

        public JwtToken ToJwtToken()
        {
            return JwtToken.LoadFromBase64String(access_token.Split('.')[1]);
        }
    }
}
