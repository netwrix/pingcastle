//
// Copyright (c) Vincent LE TOUX for Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using Newtonsoft.Json;
using PingCastle.Cloud.Credentials;
using System;
using System.Collections.Generic;
using System.Web;

namespace PingCastle.Cloud.RESTServices.Azure
{
    [AzureService("d3590ed6-52b3-4102-aeff-aad2292ab01c", "https://management.core.windows.net/")]
    public class ManagementApi : RESTClientBase<ManagementApi>, IAzureService
    {
        public ManagementApi(IAzureCredential credential) : base(credential)
        {
        }

        protected override string BuidEndPoint(string function, string optionalQuery)
        {
            var query = HttpUtility.ParseQueryString(optionalQuery);
            query["api-version"] = "2015-11-01";

            var builder = new UriBuilder("https://management.azure.com/" + function);
            builder.Query = query.ToString();
            return builder.ToString();
        }

        public TenantListResponse ListTenants()
        {
            var r = new TenantListRequest
            {
                requests = new List<TenantListRequestItem>()
                { 
                    new TenantListRequestItem {
                        httpMethod = "GET",
                        name = Guid.NewGuid().ToString(),
                        url = "/tenants?api-version=2019-03-01&`$includeAllTenantCategories=true",
                        requestHeaderDetails = new TenantListRequestHeaderDetails()
                        {
                            commandName = "fx.Services.Tenants.getTenants"
                        }
                    }
                }
            };
            return CallEndPoint<TenantListRequest, TenantListResponse>("batch", r);
        }

        public class TenantListRequestHeaderDetails
        {
            public string commandName { get; set; }
        }

        public class TenantListRequest
        {
            public List<TenantListRequestItem> requests { get; set; }
        }

        public class TenantListRequestItem
        {
            public string httpMethod { get; set; }
            public string name { get; set; }
            public TenantListRequestHeaderDetails requestHeaderDetails { get; set; }
            public string url { get; set; }
        }

        public class Headers
        {
            public string Pragma { get; set; }

            [JsonProperty("x-ms-ratelimit-remaining-tenant-reads")]
            public string XMsRatelimitRemainingTenantReads { get; set; }

            [JsonProperty("x-ms-request-id")]
            public string XMsRequestId { get; set; }

            [JsonProperty("x-ms-correlation-request-id")]
            public string XMsCorrelationRequestId { get; set; }

            [JsonProperty("x-ms-routing-request-id")]
            public string XMsRoutingRequestId { get; set; }

            [JsonProperty("Strict-Transport-Security")]
            public string StrictTransportSecurity { get; set; }

            [JsonProperty("X-Content-Type-Options")]
            public string XContentTypeOptions { get; set; }

            [JsonProperty("Cache-Control")]
            public string CacheControl { get; set; }
            public string Date { get; set; }
        }

        public class Value
        {
            public string id { get; set; }
            public string tenantId { get; set; }
            public string countryCode { get; set; }
            public string displayName { get; set; }
            public List<string> domains { get; set; }
            public string tenantCategory { get; set; }
        }

        public class Content
        {
            public List<Value> value { get; set; }
        }

        public class TenantListResponseItem
        {
            public string name { get; set; }
            public int httpStatusCode { get; set; }
            public Headers headers { get; set; }
            public Content content { get; set; }
            public int contentLength { get; set; }
        }

        public class TenantListResponse
        {
            public List<TenantListResponseItem> responses { get; set; }
        }

    }
}
