//
// Copyright (c) Vincent LE TOUX for Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Cloud.Credentials;
using PingCastle.Cloud.RESTServices.Azure;
using PingCastle.Cloud.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace PingCastle.Cloud.RESTServices
{
    [AzureService("1b730954-1685-4b74-9bfd-dac224a7b894", "https://graph.microsoft.com")]
    public class MicrosoftGraph : RESTClientBase<MicrosoftGraph>, IAzureService
    {
        public MicrosoftGraph(IAzureCredential credential) : base(credential)
        {
        }
        protected override string BuidEndPoint(string function, string optionalQuery)
        {
            var query = HttpUtility.ParseQueryString(optionalQuery);
            //query["api-version"] = "1.61-internal";

            var builder = new UriBuilder("https://graph.microsoft.com/beta/" + function);
            builder.Query = query.ToString();
            return builder.ToString();
        }

        public GraphAPI.User GetMe()
        {
            return CallEndPoint<GraphAPI.User>("me");
        }

        public List<AuthorizationPolicy> GetAuthorizationPolicy()
        {
            return CallEndPointWithPaggingAsync<object, AuthorizationPolicy>("policies/authorizationPolicy", null).GetAwaiter().GetResult();
        }

        // message=Insufficient privileges to complete the operation.
        public string GetTenantRelationships(string tenantId)
        {
            return CallEndPoint<string>("tenantRelationships/findTenantInformationByTenantId(tenantId='" + tenantId + "')");
        }

        public class AuthorizationPolicy
        {
            public string id { get; set; }
            public string allowInvitesFrom { get; set; }
            public bool allowedToSignUpEmailBasedSubscriptions { get; set; }
            public bool allowedToUseSSPR { get; set; }
            public bool allowEmailVerifiedUsersToJoinOrganization { get; set; }
            public bool blockMsolPowerShell { get; set; }
            public string description { get; set; }
            public string displayName { get; set; }
            public List<object> enabledPreviewFeatures { get; set; }
            public string guestUserRoleId { get; set; }
            public List<string> permissionGrantPolicyIdsAssignedToDefaultUserRole { get; set; }
            public UserRolePermissions defaultUserRolePermissions { get; set; }
        }

        public class UserRolePermissions
        {
            public bool allowedToCreateApps { get; set; }
            public bool allowedToCreateSecurityGroups { get; set; }
            public bool allowedToCreateTenants { get; set; }
            public bool allowedToReadBitlockerKeysForOwnedDevice { get; set; }
            public bool allowedToReadOtherUsers { get; set; }
        }
    }
}
