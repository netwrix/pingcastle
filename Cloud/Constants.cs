//
// Copyright (c) Vincent LE TOUX for Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
namespace PingCastle.Cloud
{
    public class Constants
    {
        public const string LoginEndPoint = "https://login.microsoftonline.com/";
        public const string OAuth2AuthorizeEndPoint = "https://login.microsoftonline.com/common/oauth2/authorize";
        public const string OAuth2TokenEndPoint = "https://login.microsoftonline.com/common/oauth2/token";
        public const string OAuth2NativeClientEndPoint = "urn:ietf:wg:oauth:2.0:oob";//"https://login.microsoftonline.com/common/oauth2/nativeclient";
        public const string UserRealmEndpoint = "https://login.microsoftonline.com/common/userrealm/";
        public const string UserRealmSRFEndpoint = "https://login.microsoftonline.com/GetUserRealm.srf?login=";
        public const string UserRealmCTEndpoint = "https://login.microsoftonline.com/common/GetCredentialType";
        public const string OpenIdConfigurationEndpoint = "https://login.windows.net/xxxxx/.well-known/openid-configuration";
        public const string ProvisionningEndpoint = "https://provisioningapi.microsoftonline.com/provisioningwebservice.svc";
        public const string redirectUri = "urn:ietf:wg:oauth:2.0:oob";
        public const string OrganisationsNativeClient = "https://login.microsoftonline.com/organizations/oauth2/nativeclient";
    }
}
