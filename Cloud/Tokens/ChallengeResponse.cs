//
// Copyright (c) Vincent LE TOUX for Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Cloud.Common;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;

namespace PingCastle.Cloud.RESTServices
{
    [DataContractAttribute]
    public class ChallengeResponse : JsonSerialization<ChallengeResponse>
    {
        [DataMember]
        public string Nonce { get; set; }
    }
}
