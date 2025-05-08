//
// Copyright (c) Vincent LE TOUX for Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Cloud.Common;
using PingCastle.Cloud.Credentials;
using PingCastle.Cloud.RESTServices;
using PingCastle.Cloud.RESTServices.Azure;
using PingCastle.Cloud.UI;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Xml;

namespace PingCastle.Cloud.Tokens
{
    public class TokenFactory
    {
        public static async Task<Token> GetToken<T>(IAzureCredential credential) where T : IAzureService
        {
            if (credential is PRTCredential)
            {
                Trace.WriteLine("GetToken with PRT");
                var prt = await GetPRT(credential);
                var response1 = await RunAuthorize<T>(credential, prt);
                var code = ExtractCodeFromResponse(response1);
                var service = AzureServiceAttribute.GetAzureServiceAttribute<T>();
                var token = await RunGetToken<T>(credential, code, service.RedirectUri);

                return Token.LoadFromString(token);
            }
            if (credential is CertificateCredential)
            {
                Trace.WriteLine("GetToken with Certificate");
                var certCred = (CertificateCredential)credential;
                var token = await GetTokenWithCertAsync<T>(certCred);
                return token;
            }
            Trace.WriteLine("GetToken with dialog");
            return AuthenticationDialog.Authenticate<T>(credential);
        }

        public static async Task<Token> RefreshToken<T>(string TenantId, Token token) where T : IAzureService
        {
            Trace.WriteLine("Called RefreshToken");

            var service = AzureServiceAttribute.GetAzureServiceAttribute<T>();

            var parameters = new Dictionary<string, string>()
            {
                { "client_id", service.ClientID.ToString() },
                { "grant_type", "refresh_token" },
                { "refresh_token", token.refresh_token },
            };

            var endpoint = EndPointAttribute.GetEndPointAttribute<T>();
            if (string.IsNullOrEmpty(endpoint.Scope))
            {
                parameters["resource"] = service.Resource;
                parameters["scope"] = "openid";
            }
            else
            {
                parameters["scope"] = endpoint.Scope;
            }

            var uri = endpoint.TokenEndPoint;
            if (!string.IsNullOrEmpty(TenantId))
                uri = uri.Replace("common", TenantId);

            var httpContent = new FormUrlEncodedContent(parameters);
            var httpClient = HttpClientHelper.GetHttpClient();

            using (var response = await httpClient.PostAsync(uri, httpContent))
            {
                response.EnsureSuccessStatusCode();

                if (response.Content == null)
                {
                    throw new ErrorResponseException("refresh token content is null");
                }

                var responseString = await response.Content.ReadAsStringAsync();
               
                return Token.LoadFromString(responseString);
            }
        }

        public static long ToEpochTime(DateTime date)
        {
            DateTime unixStart = new DateTime(1970, 1, 1, 0, 0, 0, 0, System.DateTimeKind.Utc);
            TimeSpan span = date - unixStart;
            return (long) span.TotalSeconds;
        }
        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        class GetTokenError : JsonSerialization<GetTokenError>
        {
            public string error { get; set; }
            public string error_description { get; set; }
            public string error_uri { get; set; }
            public string correlation_id { get; set; }
            public string trace_id { get; set; }
        }

        public static async Task<Token> GetTokenWithCertAsync<T>(CertificateCredential credential) where T : IAzureService
        {
            var service = AzureServiceAttribute.GetAzureServiceAttribute<T>();
            var httpClient = HttpClientHelper.GetHttpClient();
            var input = new Dictionary<string, string>()
                    {
                        { "client_id", credential.ClientId },
                        { "scope", service.Resource + (service.Resource.EndsWith("/") ? null : "/") + ".default"},
                        { "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
                        { "client_assertion", BuildJwtAssertion<T>(credential) },
                        { "grant_type", "client_credentials"},
                    };

            var endpoint = EndPointAttribute.GetEndPointAttribute<T>();

            using (var response = await httpClient.PostAsync(endpoint.TokenEndPoint.Replace("common", credential.Tenantid),
                new FormUrlEncodedContent(
                    input)))
            {
                string responseString = await response.Content.ReadAsStringAsync();
                if ((int)response.StatusCode >= 400)
                {
                    var error = GetTokenError.LoadFromString(responseString);
                    Console.WriteLine("Error: " + error.error);
                    Trace.WriteLine("Error: " + error.error);
                    Console.WriteLine("Description: " + error.error_description);
                    Trace.WriteLine("Description: " + error.error_description);
                    Console.WriteLine("Url: " + error.error_uri);
                    Trace.WriteLine("Url: " + error.error_uri);
                    Console.WriteLine("correlation_id: " + error.correlation_id);
                    Trace.WriteLine("correlation_id: " + error.correlation_id);
                    Console.WriteLine("trace_id: " + error.trace_id);
                    Trace.WriteLine("trace_id: " + error.trace_id);
                }
                response.EnsureSuccessStatusCode();
                return Token.LoadFromString(responseString);
            }
        }

        //https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow#second-case-access-token-request-with-a-certificate
        private static string BuildJwtAssertion<T>(CertificateCredential credential) where T : IAzureService
        {

            var header = new JwtHeader()
            {
                alg = "RS256",
                typ = "JWT",
                x5t = EncodeBase64Url(StringToByteArray(credential.ThumbPrint)),
            };
            var endpoint = EndPointAttribute.GetEndPointAttribute<T>();

            var payload = new JwtPayload()
            {
                aud = endpoint.TokenEndPoint.Replace("common", credential.Tenantid),
                exp = ToEpochTime(DateTime.UtcNow.AddHours(1)),
                iss = credential.ClientId,
                jti = Guid.NewGuid().ToString(),
                nbf = ToEpochTime(DateTime.UtcNow.AddHours(-1)),
                sub = credential.ClientId,
                iat = ToEpochTime(DateTime.UtcNow),
            };
            string rawHeader = header.ToBase64UrlJsonString();
            string rawPayload = payload.ToBase64UrlJsonString();
            byte[] toSign = Encoding.UTF8.GetBytes(rawHeader + "." + rawPayload);
            using (SHA256 hashstring = SHA256.Create())
            {
                byte[] signature = ((RSACryptoServiceProvider)credential.PrivateKey).SignData(toSign, hashstring);
                // RSASSA-PKCS1-v1_5 with the SHA-256 hash algorithm
                return rawHeader + "." + rawPayload + "." + EncodeBase64Url(signature);
            }
        }

        public static string EncodeBase64Url(byte[] arg)
        {
            var s = Convert.ToBase64String(arg);
            return s
                .Replace("=", "")
                .Replace("/", "_")
                .Replace("+", "-")
                .Replace("=", "");
        }

        private static string ExtractCodeFromResponse(string response1)
        {
            try
            {
                Trace.WriteLine("ExtractCodeFromResponse");
                string code = null;
                XmlDocument xmlDoc = new XmlDocument();

                using (var ms = new MemoryStream())
                {
                    var bytes = Encoding.UTF8.GetBytes(response1);
                    ms.Write(bytes, 0, bytes.Length);
                    ms.Position = 0;
                    xmlDoc.Load(ms);
                }

                XmlNode titleNode = xmlDoc.SelectSingleNode("//html/body/script");

                if (titleNode != null)
                {
                    Trace.WriteLine("TitleNode found");
                    code = titleNode.InnerText.Split('?')[1].Split('\\')[0].Split('=')[1];
                }
                else
                {
                    Trace.WriteLine("TitleNode not found");
                    var hrefNode = xmlDoc.SelectSingleNode("//html/body/h2/a/@href");
                    if (hrefNode != null)
                    {
                        Trace.WriteLine("A href found");
                        var link = hrefNode.InnerText;
                        var builder = new UriBuilder(link);
                        var query = HttpUtility.ParseQueryString(builder.Query);
                        if (!string.IsNullOrEmpty(query["code"]))
                        {
                            Trace.WriteLine("code found");
                            return query["code"];
                        }
                        if (query["sso_nonce"] != null)
                        {
                            Trace.WriteLine("sso_nonce found");
                            var sso_nonce = query["sso_nonce"];
                            throw new ApplicationException("SSO_Nonce " + sso_nonce);
                        }
                    }
                    else
                    {
                        throw new NotImplementedException();
                    }
                }
                return code;
            }
            catch (Exception)
            {
                Trace.WriteLine("Exception when processing extract code");
                Trace.WriteLine(response1);
                Trace.WriteLine("===");
                throw;
            }
        }

        private static async Task<string> GetPRT(IAzureCredential credential)
        {
            var httpClient = HttpClientHelper.GetHttpClient();

            ChallengeResponse cr;
            using (var response = await httpClient.PostAsync(Constants.OAuth2TokenEndPoint,
                new FormUrlEncodedContent(
                    new Dictionary<string, string>()
                    {
                        {"grant_type", "srv_challenge"},
                    })))
            {
                var r = await response.Content.ReadAsStringAsync();
                cr = ChallengeResponse.LoadFromString(r);
            }
            string aep = Constants.OAuth2AuthorizeEndPoint;
            if (!string.IsNullOrEmpty(credential.TenantidToQuery))
            {
                aep = aep.Replace("common", credential.TenantidToQuery);
            }
            string uri = HttpClientHelper.BuildUri(aep,
                new Dictionary<string, string> {
                    { "sso_nonce", cr.Nonce } ,
                });
            var o = CookieInfoManager.GetCookieInforForUri(uri);
            var token = o[0].Data.Split(';')[0];
            return token;
        }

        public static List<JwtToken> GetRegisteredPRTIdentities()
        {
            var output = new List<JwtToken>();
            Trace.WriteLine("GetRegisteredPRTIdentities");
            var o = CookieInfoManager.GetCookieInforForUri(Constants.OAuth2TokenEndPoint);
            if (o != null)
            {
                Trace.WriteLine(o.Count + " identities");
                foreach (var i in o)
                {
                    Trace.WriteLine("Identity: " + i.Data);
                    var prtToken = i.Data.Split(';')[0];
                    var sections = prtToken.Split('.');
                    if (sections.Length < 2)
                        continue;
                    var payload = sections[1];
                    Trace.WriteLine("Before loading token");
                    JwtToken t = JwtToken.LoadFromBase64String(payload);
                    Trace.WriteLine("Token: " + t.unique_name);
                    output.Add(t);
                }
            }
            else
            {
                Trace.WriteLine("No identity");
            }
            return output;
        }

        private static async Task<string> RunAuthorize<T>(IAzureCredential credential, string prtToken) where T : IAzureService
        {
            var sections = prtToken.Split('.');
            if (sections.Length < 2)
                throw new ApplicationException("PrtToken with Lenght < 2: " + prtToken);

            var payload = sections[1];

            JwtToken t = JwtToken.LoadFromBase64String(payload);

            var mscrid = Guid.NewGuid();
            var requestId = mscrid;

            var service = AzureServiceAttribute.GetAzureServiceAttribute<T>();

            var aep = Constants.OAuth2AuthorizeEndPoint;
            if (!string.IsNullOrEmpty(credential.TenantidToQuery))
            {
                aep = aep.Replace("common", credential.TenantidToQuery);
            }

            Trace.WriteLine("RunAuthorize: post to " + aep);

            string uri = HttpClientHelper.BuildUri(aep,
                new Dictionary<string, string> {
                    { "resource", service.Resource } ,
                    { "client_id", service.ClientID.ToString()},
                    { "response_type", "code" },
                    { "redirect_uri", service.RedirectUri},
                    { "client-request-id", requestId.ToString()},
                    { "mscrid", mscrid.ToString()},
                    { "sso_nonce", t.request_nonce}
                });

            var httpClient = HttpClientHelper.GetHttpClient();

            using (var request = new HttpRequestMessage(HttpMethod.Get, uri))
            {
                request.Headers.Add("x-ms-RefreshTokenCredential", prtToken);
                var response = await httpClient.SendAsync(request);

                return await response.Content.ReadAsStringAsync();
            }
        }

        public static async Task<string> RunGetToken<T>(IAzureCredential credential, string code, string redirectUri, string code_verifier = null) where T : IAzureService
        {
            var service = AzureServiceAttribute.GetAzureServiceAttribute<T>();
            var endpoint = EndPointAttribute.GetEndPointAttribute<T>();
            var httpClient = HttpClientHelper.GetHttpClient();
            var input = new Dictionary<string, string>()
                    {
                        { "client_id", service.ClientID.ToString() },
                        { "grant_type", "authorization_code" },
                        { "code", code },
                        { "redirect_uri", redirectUri },
                        { "scope", "openid profile email offline_access" },
                    };

            if (!string.IsNullOrEmpty(code_verifier))
            {
                input.Add("code_verifier", code_verifier);
            }
            
            var tep = endpoint.TokenEndPoint;
            if (!string.IsNullOrEmpty(credential.TenantidToQuery))
            {
                tep = tep.Replace("common", credential.TenantidToQuery);
            }
            Trace.WriteLine("RunGetToken: post to " + tep);
            using (var response = await httpClient.PostAsync(tep,
                new FormUrlEncodedContent(
                    input)))
            {
                response.EnsureSuccessStatusCode();

                return await response.Content.ReadAsStringAsync();
            }
        }
    }
}
