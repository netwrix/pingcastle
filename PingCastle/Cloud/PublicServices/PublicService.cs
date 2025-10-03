//
// Copyright (c) Vincent LE TOUX for Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Cloud.Common;
using System.Net.Http;
using System.Threading.Tasks;

namespace PingCastle.Cloud.PublicServices
{
    public class PublicService
    {
        public  static async Task<UserRealmV1> GetUserRealmv1(string domain)
        {
            var httpClient = HttpClientHelper.GetHttpClient();

            var response = await httpClient.GetStringAsync(Constants.UserRealmEndpoint + domain + "?api-version=1.0");

            return UserRealmV1.LoadFromString(response);
        }

        public static async Task<UserRealmV2> GetUserRealmV2(string domain)
        {
            var httpClient = HttpClientHelper.GetHttpClient();

            var response = await httpClient.GetStringAsync(Constants.UserRealmEndpoint + domain + "?api-version=2.0");

            return UserRealmV2.LoadFromString(response);
        }

        public static async Task<UserRealmSRF> GetUserRealmSRF(string domain)
        {
            var httpClient = HttpClientHelper.GetHttpClient();

            var response = await httpClient.GetStringAsync(Constants.UserRealmSRFEndpoint + domain);

            return UserRealmSRF.LoadFromString(response);
        }

        public static async Task<UserRealmCT> GetUserRealmCT(string email)
        {
            var httpClient = HttpClientHelper.GetHttpClient();

            var request = new UserRealmCTRequest
            {
                username = email,
                isOtherIdpSupported = true,
                checkPhones = true,
                isRemoteNGCSupported = false,
                isCookieBannerShown = false,
                isFidoSupported = false,
                originalRequest = "",
                flowToken = ""
            };

            var stringContent = new StringContent(request.ToJsonString());
            var response = await httpClient.PostAsync(Constants.UserRealmCTEndpoint, stringContent);
            var t = await response.Content.ReadAsStringAsync();
            return UserRealmCT.LoadFromString(t);
        }

        public static async Task<OpenIDConfiguration> GetOpenIDConfiguration(string domain)
        {
            var httpClient = HttpClientHelper.GetHttpClient();

            var response = await httpClient.GetStringAsync(Constants.OpenIdConfigurationEndpoint.Replace("xxxxx", domain));

            return OpenIDConfiguration.LoadFromString(response);
        }

    }
}
