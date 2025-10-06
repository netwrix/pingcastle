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
    public class AzureServiceAttribute : Attribute
    {
        public AzureServiceAttribute(string ClientID, string Resource, string RedirectUri = Constants.redirectUri)
        {
            this.ClientID = Guid.Parse(ClientID);
            this.Resource = Resource;
            this.RedirectUri = RedirectUri;
        }
        public Guid ClientID { get; set; }
        public string Resource { get; set; }
        public string RedirectUri { get; set; }

        public static AzureServiceAttribute GetAzureServiceAttribute<T>() where T : IAzureService
        {
            AzureServiceAttribute[] attrs = (AzureServiceAttribute[])typeof(T).GetCustomAttributes(typeof(AzureServiceAttribute));
            if (attrs.Length > 0)
                return attrs[0];
            throw new ApplicationException("no service attribute found");
        }
    }


}
