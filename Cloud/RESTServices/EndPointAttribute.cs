//
// Copyright (c) Vincent LE TOUX for Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Reflection;

namespace PingCastle.Cloud.RESTServices.Azure
{
    public class EndPointAttribute : Attribute
    {
        public EndPointAttribute(string authorize, string token, string scope = null)
        {
            AuthorizeEndPoint = authorize;
            TokenEndPoint = token;
            Scope = scope;
        }

        public string AuthorizeEndPoint { get; private set; }
        public string TokenEndPoint { get; private set; }
        public string Scope { get; private set; }

        public static EndPointAttribute GetEndPointAttribute<T>() where T : IAzureService
        {
            EndPointAttribute[] attrs = (EndPointAttribute[])typeof(T).GetCustomAttributes(typeof(EndPointAttribute));
            if (attrs.Length > 0)
                return attrs[0];
            return DefaultEndPointAttribute();
        }

        private static EndPointAttribute DefaultEndPointAttribute()
        {
            return new EndPointAttribute(Constants.OAuth2AuthorizeEndPoint, Constants.OAuth2TokenEndPoint);
        }
    }


}
