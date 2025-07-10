//
// Copyright (c) Vincent LE TOUX for Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Cloud.Credentials;
using System;
using System.Web;

namespace PingCastle.Cloud.RESTServices.Azure
{
    [AzureService("d3590ed6-52b3-4102-aeff-aad2292ab01c", "74658136-14ec-4630-ad9b-26e160ff0fc6")]
    public class AzureADConnectApi : RESTClientBase<AzureADConnectApi>, IAzureService
    {
        public AzureADConnectApi(IAzureCredential credential) : base(credential)
        {
        }

        protected override string BuidEndPoint(string function, string optionalQuery)
        {
            var query = HttpUtility.ParseQueryString(optionalQuery);
            query["api-version"] = "2.0";

            var builder = new UriBuilder("https://main.iam.ad.ext.azure.com/api/Directories/" + function);
            builder.Query = query.ToString();
            return builder.ToString();
        }

        public ADConnectStatusResponse ADConnectStatus()
        {
            return CallEndPoint<ADConnectStatusResponse>("ADConnectStatus");
        }

        public class ADConnectStatusResponse
        {
            public int verifiedDomainCount { get; set; }
            public int verifiedCustomDomainCount { get; set; }
            public int federatedDomainCount { get; set; }
            public int? numberOfHoursFromLastSync { get; set; }
            public bool? dirSyncEnabled { get; set; }
            public bool? dirSyncConfigured { get; set; }
            public bool? passThroughAuthenticationEnabled { get; set; }
            public bool? seamlessSingleSignOnEnabled { get; set; }
        }
    }
}
