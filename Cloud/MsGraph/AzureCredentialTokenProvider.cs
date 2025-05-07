using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Kiota.Abstractions.Authentication;
using PingCastle.Cloud.Credentials;
using PingCastle.Cloud.RESTServices.Azure;

namespace PingCastle.Cloud.MsGraph
{
    public class AzureCredentialTokenProvider<T> : IAccessTokenProvider where T : IAzureService
    {
        private readonly IAzureCredential _credential;

        public AzureCredentialTokenProvider(IAzureCredential credential)
        {
            _credential = credential;
        }

        public async Task<string> GetAuthorizationTokenAsync(Uri uri, Dictionary<string, object> additionalAuthenticationContext = default, CancellationToken cancellationToken = default)
        {
            Trace.WriteLine($"ACTP: the token has been requested {uri}");
            var token = await _credential.GetToken<T>();
            return token.access_token;
        }

        public AllowedHostsValidator AllowedHostsValidator => new AllowedHostsValidator();
    }
}
