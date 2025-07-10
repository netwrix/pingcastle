//
// Copyright (c) Vincent LE TOUX for Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Cloud.Common;
using System.Collections.Generic;
using System.Runtime.Serialization;

namespace PingCastle.Cloud.PublicServices
{
    [DataContractAttribute]
    public class UserRealmCT : JsonSerialization<UserRealmCT>
    {
        [DataMember]
        public string Username { get; set; }
        [DataMember]
        public string Display { get; set; }
        [DataMember]
        public int IfExistsResult { get; set; }
        [DataMember]
        public bool IsUnmanaged { get; set; }
        [DataMember]
        public int ThrottleStatus { get; set; }
        [DataMember]
        public UserRealmCTCredentials Credentials { get; set; }
        [DataMember]
        public UserRealmCTEstsProperties EstsProperties { get; set; }
        [DataMember]
        public string FlowToken { get; set; }
        [DataMember]
        public bool IsSignupDisallowed { get; set; }
        [DataMember]
        public string apiCanary { get; set; }
    }

    public class UserRealmCTCredentials
    {
        [DataMember]
        public int PrefCredential { get; set; }
        [DataMember]
        public bool HasPassword { get; set; }
        [DataMember]
        public string RemoteNgcParams { get; set; }
        [DataMember]
        public string FidoParams { get; set; }
        [DataMember]
        public string SasParams { get; set; }
        [DataMember]
        public string CertAuthParams { get; set; }
        [DataMember]
        public string GoogleParams { get; set; }
        [DataMember]
        public string FacebookParams { get; set; }
        [DataMember]
        public string FederationRedirectUrl { get; set; }
    }

    public class UserRealmCTEstsProperties
    {
        [DataMember]
        public List<TenantBrandingInfo> UserTenantBranding { get; set; }
        [DataMember]
        public int DomainType { get; set; }
        
    }
}
