﻿using Microsoft.Graph;
using Microsoft.Graph.Beta;
using Microsoft.Kiota.Abstractions.Authentication;
using PingCastle.Cloud.Credentials;
using PingCastle.Cloud.RESTServices.Azure;

namespace PingCastle.Cloud.MsGraph
{
    public static class GraphServiceClientFactory
    {
        public static GraphServiceClient Create(string accessToken)
        {
            return Create(new SimpleAccessTokenProvider(accessToken));
        }

        public static GraphServiceClient Create<T>(IAzureCredential credential) where T : IAzureService
        {
            return Create(new AzureCredentialTokenProvider<T>(credential));
        }

        public static GraphServiceClient Create(IAccessTokenProvider tokenProvider)
        {
            var authProvider = new BaseBearerTokenAuthenticationProvider(tokenProvider);
            var httpClient = GraphClientFactory.Create(authProvider, version: "beta");

            return new GraphServiceClient(httpClient);
        }
    }
}
