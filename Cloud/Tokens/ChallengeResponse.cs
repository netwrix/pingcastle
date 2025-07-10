//
// Copyright (c) Vincent LE TOUX for Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Cloud.Common;
using System.Runtime.Serialization;

namespace PingCastle.Cloud.RESTServices
{
    [DataContractAttribute]
    public class ChallengeResponse : JsonSerialization<ChallengeResponse>
    {
        [DataMember]
        public string Nonce { get; set; }
    }
}
