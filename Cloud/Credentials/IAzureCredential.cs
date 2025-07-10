//
// Copyright (c) Vincent LE TOUX for Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Cloud.RESTServices.Azure;
using PingCastle.Cloud.Tokens;
using System.Threading.Tasks;

namespace PingCastle.Cloud.Credentials
{
    public interface IAzureCredential
    {
        string Tenantid { get; }
        string TenantidToQuery { get; set; }
        Task<Token> GetToken<T>() where T : IAzureService;
        Token LastTokenQueried { get; }
        bool ForceRefreshByRefreshToken { get; set; }
    }
}
