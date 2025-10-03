using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Kiota.Abstractions.Authentication;
using System;

namespace PingCastle.Cloud.MsGraph
{
    public class SimpleAccessTokenProvider : IAccessTokenProvider
    {
        private readonly string _accessToken;

        public SimpleAccessTokenProvider(string accessToken)
        {
            _accessToken = accessToken;
        }

        public async Task<string> GetAuthorizationTokenAsync(Uri uri, Dictionary<string, object> additionalAuthenticationContext = default, CancellationToken cancellationToken = default)
        {
            return await Task.FromResult(_accessToken);
        }

        public AllowedHostsValidator AllowedHostsValidator => new AllowedHostsValidator();
    }
}
