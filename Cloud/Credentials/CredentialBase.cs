//
// Copyright (c) Vincent LE TOUX for Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Cloud.RESTServices.Azure;
using PingCastle.Cloud.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PingCastle.Cloud.Credentials
{
    public abstract class CredentialBase : IAzureCredential
    {
        public CredentialBase() : this(null)
        {

        }
        public CredentialBase(string tenantid)
        {
            this.tenantId = tenantid;
        }

        Dictionary<Type, Token> cache = new Dictionary<Type, Token>();
        public Token LastTokenQueried { get; protected set; }
        public async Task<Token> GetToken<T>() where T : IAzureService
        {
            Token token;
            if (cache.ContainsKey(typeof(T)))
            {
                token = cache[typeof(T)];

                // TODO refresh

                return token;
            }
            token = await TokenFactory.GetToken<T>(this);
            LastTokenQueried = token;
            cache[typeof(T)] = token;
            return token;
        }
        string tenantId;
        public string Tenantid
        {
            get
            {
                if (string.IsNullOrEmpty(tenantId) && cache.Count > 0)
                {
                    var token = cache.Values.FirstOrDefault();
                    tenantId = token.ToJwtToken().tid;
                }
                return tenantId;
            }
        }

        string tenantidToQuery;
        public string TenantidToQuery
        {
            get
            {
                return tenantidToQuery;
            }
            set
            {
                if (tenantidToQuery == value)
                    return;
                if (string.IsNullOrEmpty(value))
                    return;
                tenantidToQuery = value;
                cache.Clear();
            }
        }
    }
}
