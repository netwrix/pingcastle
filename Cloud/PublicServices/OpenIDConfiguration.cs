//
// Copyright (c) Vincent LE TOUX for Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Cloud.Common;
using System.Runtime.Serialization;

namespace PingCastle.Cloud.PublicServices
{
    [DataContractAttribute]
    public class OpenIDConfiguration : JsonSerialization<OpenIDConfiguration>
    {
        [DataMember]
        public string token_endpoint { get; set; }
        [DataMember]
        public string[] token_endpoint_auth_methods_supported { get; set; }
        [DataMember]
        public string[] response_modes_supported { get; set; }
        [DataMember]
        public string[] subject_types_supported { get; set; }
        [DataMember]
        public string[] id_token_signing_alg_values_supported { get; set; }
        [DataMember]
        public string[] response_types_supported { get; set; }
        [DataMember]
        public string[] scopes_supported { get; set; }
        [DataMember]
        public string issuer { get; set; }
        [DataMember]
        public bool microsoft_multi_refresh_token { get; set; }
        [DataMember]
        public string authorization_endpoint { get; set; }
        [DataMember]
        public string device_authorization_endpoint { get; set; }
        [DataMember]
        public bool http_logout_supported { get; set; }
        [DataMember]
        public bool frontchannel_logout_supported { get; set; }
        [DataMember]
        public string end_session_endpoint { get; set; }
        [DataMember]
        public string[] claims_supported { get; set; }
        [DataMember]
        public string check_session_iframe { get; set; }
        [DataMember]
        public string userinfo_endpoint { get; set; }
        [DataMember]
        public string kerberos_endpoint { get; set; }
        [DataMember]
        public string tenant_region_scope { get; set; }
        [DataMember]
        public string cloud_instance_name { get; set; }
        [DataMember]
        public string cloud_graph_host_name { get; set; }
        [DataMember]
        public string msgraph_host { get; set; }
        [DataMember]
        public string rbac_url { get; set; }
    }
}
