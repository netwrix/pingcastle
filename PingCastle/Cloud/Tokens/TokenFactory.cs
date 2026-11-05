namespace PingCastle.Cloud.Tokens
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Diagnostics.CodeAnalysis;
    using System.DirectoryServices.Protocols;
    using System.IO;
    using System.Linq;
    using System.Net.Http;
    using System.Security.Cryptography;
    using System.Text;
    using System.Text.RegularExpressions;
    using System.Threading.Tasks;
    using System.Web;
    using System.Xml;
    using PingCastle.Cloud.Common;
    using PingCastle.Cloud.Credentials;
    using PingCastle.Cloud.RESTServices;
    using PingCastle.Cloud.RESTServices.Azure;
    using PingCastle.Cloud.UI;
    using PingCastle.UserInterface;
    using PingCastleCommon.Utility;

    /// <summary>
    /// Handles retrieval of tokens from authentication providers.
    /// </summary>
    public class TokenFactory : ITokenFactory
    {
        /// <summary>
        /// Retrieves a token from an authentication provider's credential.
        /// </summary>
        /// <typeparam name="T">They type of the Azure service.</typeparam>
        /// <param name="credential">The credential to use for authentication.</param>
        /// <returns>A new <see cref="Token"/>.</returns>
        public async Task<Token> GetToken<T>(IAzureCredential credential)
            where T : IAzureService
        {
            if (credential is PRTCredential)
            {
                Trace.WriteLine("GetToken with PRT");
                try
                {
                    var prt = await GetPRT(credential);
                    var authorisationResponse = await RunAuthorize<T>(credential, prt);

                    // Attempt to extract code from response
                    Result<string> result = ExtractCodeFromResponse(authorisationResponse);
                    if (result.IsSuccess)
                    {
                        var service = AzureServiceAttribute.GetAzureServiceAttribute<T>();
                        var token = await RunGetToken<T>(credential, result.Value, service.RedirectUri);
                        return Token.LoadFromString(token);
                    }

                    Trace.WriteLine("MFA likely required, continuing authentication flow");

                    // Check if the response contains HTML that should be shown to the user
                    if (IsHtmlToBeShownToUser(authorisationResponse))
                    {
                        Trace.WriteLine("HTML content detected that requires user interaction");
                        return AuthenticationDialog.CompleteAuthenticationWithHtml<T>(credential, authorisationResponse, this);
                    }

                    // Extract the URL from the response to continue the authentication
                    string authUrl = ExtractAuthUrlFromResponse(authorisationResponse);
                    if (!string.IsNullOrEmpty(authUrl))
                    {
                        return AuthenticationDialog.ContinueAuthentication<T>(credential, authUrl, this);
                    }

                    Trace.WriteLine("Could not extract authentication URL, falling back to regular authentication");
                }
                catch (ApplicationException aex)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    Trace.WriteLine($"Error during PRT authentication: {ex.Message}");
                }
            }

            if (credential is CertificateCredential certCredential)
            {
                Trace.WriteLine("GetToken with Certificate");
                var token = await GetTokenWithCertAsync<T>(certCredential);
                return token;
            }

            Trace.WriteLine("GetToken with dialog");
            return AuthenticationDialog.Authenticate<T>(credential);
        }

        /// <summary>
        /// Refreshes the token for a given tenant identity.
        /// </summary>
        /// <typeparam name="T">The type of AzureService to process.</typeparam>
        /// <param name="tenantId">The identity of the tenant.</param>
        /// <param name="token">The <see cref="Token"/> that needs to be refreshed.</param>
        /// <returns>A new <see cref="Token"/>.</returns>
        /// <exception cref="InvalidOperationException">Thrown when the authorization service returns a token with no content.</exception>
        public async Task<Token> RefreshToken<T>(string tenantId, Token token)
            where T : IAzureService
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
                parameters["scope"] = "openid profile email offline_access " + service.Resource + "/.default";
            }
            else
            {
                parameters["scope"] = endpoint.Scope;
            }

            var uri = endpoint.TokenEndPoint;
            if (!string.IsNullOrEmpty(tenantId))
            {
                uri = uri.Replace("common", tenantId);
            }

            var httpContent = new FormUrlEncodedContent(parameters);
            var httpClient = HttpClientHelper.GetHttpClient();

            using var response = await httpClient.PostAsync(uri, httpContent);
            response.EnsureSuccessStatusCode();

            if (response.Content == null)
            {
                throw new InvalidOperationException("refresh token content is null");
            }

            var responseString = await response.Content.ReadAsStringAsync();

            return Token.LoadFromString(responseString);
        }

        /// <summary>
        /// Retrieves the PRT identities stored on this computer.
        /// </summary>
        /// <returns>A list of <see cref="JwtToken"/> containing the found identities.</returns>
        public List<JwtToken> GetRegisteredPRTIdentities()
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
                    {
                        continue;
                    }

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

        /// <summary>
        /// Retrieves an access token from Azure using the authorization code flow.
        /// </summary>
        /// <typeparam name="T">The Azure Service type to work with.</typeparam>
        /// <param name="credential">The credential to retrieve the token for.</param>
        /// <param name="code">The authorization code.</param>
        /// <param name="redirectUri">The redirect URI for the authorization flow.</param>
        /// <param name="codeVerifier">The code verifier.</param>
        /// <returns>A new <see cref="string"/> containing the access token.</returns>
        public async Task<string> RunGetToken<T>(
            IAzureCredential credential,
            string code,
            string redirectUri,
            string codeVerifier = null)
            where T : IAzureService
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

            if (!string.IsNullOrEmpty(codeVerifier))
            {
                input.Add("code_verifier", codeVerifier);
            }

            var tep = endpoint.TokenEndPoint;
            if (!string.IsNullOrEmpty(credential.TenantidToQuery))
            {
                tep = tep.Replace("common", credential.TenantidToQuery);
            }

            Trace.WriteLine("RunGetToken: post to " + tep);
            using var response = await httpClient.PostAsync(tep, new FormUrlEncodedContent(input));
            response.EnsureSuccessStatusCode();

            return await response.Content.ReadAsStringAsync();
        }

        private static string ExtractAuthUrlFromResponse(string htmlResponse)
        {
            if (htmlResponse.IsNullOrEmpty())
            {
                Trace.WriteLine("Empty HTML response received");
                return null;
            }

            string url = null;

            try
            {
                // Strategy 1: Check for JavaScript redirects (most common)
                url = ExtractJavaScriptRedirect(htmlResponse);
                if (url != null)
                {
                    return url;
                }

                // Strategy 2: Check for HTML form actions
                url = ExtractFormAction(htmlResponse);
                if (url != null)
                {
                    return url;
                }

                // Strategy 3: Check for meta refresh redirects
                url = ExtractMetaRefresh(htmlResponse);
                if (url != null)
                {
                    return url;
                }

                Trace.WriteLine("No authentication URL found in response");
            }
            catch (Exception ex)
            {
                Trace.WriteLine($"Authentication URL extraction failed: {ex.Message}");
#if DEBUG
                Trace.WriteLine($"Stack trace: {ex.StackTrace}");
#endif
            }

            return url;
        }

        private static string ExtractJavaScriptRedirect(string html)
        {
            // Using compiled regex patterns for better performance
            var jsRedirectPatterns = new[]
            {
                new Regex(@"window\.location(?:\.href)?\s*=\s*[""']([^""']+)[""']", RegexOptions.Compiled | RegexOptions.IgnoreCase),
                new Regex(@"location\.href\s*=\s*[""']([^""']+)[""']", RegexOptions.Compiled | RegexOptions.IgnoreCase),
                new Regex(@"window\.location\.(?:replace|assign)\([""']([^""']+)[""']\)", RegexOptions.Compiled | RegexOptions.IgnoreCase),
            };

            foreach (var pattern in jsRedirectPatterns)
            {
                var match = pattern.Match(html);
                if (match.Success)
                {
                    var url = match.Groups[1].Value;
                    Trace.WriteLine($"Found JavaScript redirect URL: {url}");
                    return url;
                }
            }

            return null;
        }

        private static string ExtractFormAction(string html)
        {
            try
            {
                // Use a lightweight approach first with regex
                var formMatch = Regex.Match(
                    html,
                    @"<form\s+[^>]*action\s*=\s*[""']([^""']+)[""'][^>]*>",
                    RegexOptions.IgnoreCase | RegexOptions.Singleline);

                if (formMatch.Success)
                {
                    var url = formMatch.Groups[1].Value;
                    Trace.WriteLine($"Found form action URL: {url}");
                    return url;
                }

                // If regex fails, fall back to HTML parsing for more complex cases
                using var reader = new StringReader(html);
                var doc = new HtmlAgilityPack.HtmlDocument
                {
                    OptionFixNestedTags = true,
                };
                doc.Load(reader);

                var formNode = doc.DocumentNode.SelectSingleNode("//form[@action]");
                if (formNode != null)
                {
                    var url = formNode.GetAttributeValue("action", null);
                    if (!string.IsNullOrEmpty(url))
                    {
                        Trace.WriteLine($"Found form action URL via HTML parsing: {url}");
                        return url;
                    }
                }
            }
            catch (Exception ex)
            {
                Trace.WriteLine($"Form action extraction error: {ex.Message}");
            }

            return null;
        }

        private static string ExtractMetaRefresh(string html)
        {
            try
            {
                var metaRefreshMatch = Regex.Match(
                    html,
                    @"<meta\s+[^>]*http-equiv\s*=\s*[""']refresh[""'][^>]*content\s*=\s*[""'][^""']*url\s*=\s*([^""']+)[""'][^>]*>",
                    RegexOptions.IgnoreCase | RegexOptions.Singleline);

                if (metaRefreshMatch.Success)
                {
                    var url = metaRefreshMatch.Groups[1].Value;
                    Trace.WriteLine($"Found meta refresh URL: {url}");
                    return HtmlDecode(url);
                }

                // Alternative format for meta refresh
                metaRefreshMatch = Regex.Match(
                    html,
                    @"<meta\s+[^>]*content\s*=\s*[""'][^""']*url\s*=\s*([^""']+)[""'][^>]*http-equiv\s*=\s*[""']refresh[""'][^>]*>",
                    RegexOptions.IgnoreCase | RegexOptions.Singleline);

                if (metaRefreshMatch.Success)
                {
                    var url = metaRefreshMatch.Groups[1].Value;
                    Trace.WriteLine($"Found meta refresh URL (alt format): {url}");
                    return HtmlDecode(url);
                }
            }
            catch (Exception ex)
            {
                Trace.WriteLine($"Meta refresh extraction error: {ex.Message}");
            }

            return null;
        }

        private static string HtmlDecode(string text)
        {
            return string.IsNullOrEmpty(text) ? text : System.Net.WebUtility.HtmlDecode(text);
        }

        private static long ToEpochTime(DateTime date)
        {
            DateTime unixStart = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            TimeSpan span = date - unixStart;
            return (long)span.TotalSeconds;
        }

        private static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        private static async Task<Token> GetTokenWithCertAsync<T>(CertificateCredential credential)
            where T : IAzureService
        {
            var service = AzureServiceAttribute.GetAzureServiceAttribute<T>();
            var httpClient = HttpClientHelper.GetHttpClient();
            var input = new Dictionary<string, string>()
            {
                { "client_id", credential.ClientId },
                { "scope", service.Resource + (service.Resource.EndsWith("/") ? null : "/") + ".default" },
                { "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" },
                { "client_assertion", BuildJwtAssertion<T>(credential) },
                { "grant_type", "client_credentials" },
            };

            var endpoint = EndPointAttribute.GetEndPointAttribute<T>();

            using var response = await httpClient.PostAsync(
                endpoint.TokenEndPoint.Replace("common", credential.Tenantid),
                new FormUrlEncodedContent(input));
            string responseString = await response.Content.ReadAsStringAsync();
            if ((int)response.StatusCode >= 400)
            {
                IUserInterface io = UserInterfaceFactory.GetUserInterface();

                var error = GetTokenError.LoadFromString(responseString);
                io.DisplayMessage("Error: " + error.error);
                Trace.WriteLine("Error: " + error.error);
                io.DisplayMessage("Description: " + error.error_description);
                Trace.WriteLine("Description: " + error.error_description);
                io.DisplayMessage("Url: " + error.error_uri);
                Trace.WriteLine("Url: " + error.error_uri);
                io.DisplayMessage("correlation_id: " + error.correlation_id);
                Trace.WriteLine("correlation_id: " + error.correlation_id);
                io.DisplayMessage("trace_id: " + error.trace_id);
                Trace.WriteLine("trace_id: " + error.trace_id);
            }

            response.EnsureSuccessStatusCode();
            return Token.LoadFromString(responseString);
        }

        // https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow#second-case-access-token-request-with-a-certificate
        private static string BuildJwtAssertion<T>(CertificateCredential credential)
            where T : IAzureService
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
            using SHA256 hashService = SHA256.Create();
            byte[] signature = ((RSACryptoServiceProvider)credential.PrivateKey).SignData(toSign, hashService);

            // RSASSA-PKCS1-v1_5 with the SHA-256 hash algorithm
            return rawHeader + "." + rawPayload + "." + EncodeBase64Url(signature);
        }

        private static string EncodeBase64Url(byte[] arg)
        {
            var s = Convert.ToBase64String(arg);
            return s
                .Replace("=", string.Empty)
                .Replace("/", "_")
                .Replace("+", "-")
                .Replace("=", string.Empty);
        }

        private static Result<string> ExtractCodeFromResponse(string response1)
        {
            try
            {
                Trace.WriteLine("ExtractCodeFromResponse");

                try
                {
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
                        var code = titleNode.InnerText.Split('?')[1].Split('\\')[0].Split('=')[1];
                        return code;
                    }

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
                }
                catch (XmlException ex)
                {
                    Trace.WriteLine("XML parsing failed: " + ex.Message);

                    // This looks for code= followed by a long string until \u0026 or " or end of string
                    var codePattern = @"[?&]code=([^""]+?)(?:\\u0026|""|$)";
                    var codeMatch = Regex.Match(response1, codePattern);

                    if (codeMatch.Success)
                    {
                        Trace.WriteLine("Code extracted using regex");
                        return codeMatch.Groups[1].Value;
                    }

                    // Check for sso_nonce with regex
                    var nonceMatch = Regex.Match(response1, @"[?&]sso_nonce=([^&""]+)");
                    if (nonceMatch.Success)
                    {
                        Trace.WriteLine("sso_nonce found using regex");
                        return new ApplicationException("SSO_Nonce " + nonceMatch.Groups[1].Value);
                    }

                    // Failed all attempts, so rethrow.
                    return ex;
                }
            }
            catch (Exception ex)
            {
                return ex;
            }

            return null;
        }

        private static async Task<string> GetPRT(IAzureCredential credential)
        {
            var httpClient = HttpClientHelper.GetHttpClient();

            ChallengeResponse cr;
            using (var response = await httpClient.PostAsync(
                Constants.OAuth2TokenEndPoint,
                new FormUrlEncodedContent(
                    new Dictionary<string, string>()
                    {
                        { "grant_type", "srv_challenge" },
                    }))
            )
            {
                var r = await response.Content.ReadAsStringAsync();
                cr = ChallengeResponse.LoadFromString(r);
            }

            string aep = Constants.OAuth2AuthorizeEndPoint;
            if (!string.IsNullOrEmpty(credential.TenantidToQuery))
            {
                aep = aep.Replace("common", credential.TenantidToQuery);
            }

            string uri = HttpClientHelper.BuildUri(
                aep,
                new Dictionary<string, string>
                {
                    { "sso_nonce", cr.Nonce },
                });
            var o = CookieInfoManager.GetCookieInforForUri(uri);
            var token = o[0].Data.Split(';')[0];
            return token;
        }

        private static async Task<string> RunAuthorize<T>(IAzureCredential credential, string prtToken)
            where T : IAzureService
        {
            var sections = prtToken.Split('.');
            if (sections.Length < 2)
            {
                throw new ApplicationException("PrtToken with Length < 2: " + prtToken);
            }

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

            string uri = HttpClientHelper.BuildUri(
                aep,
                new Dictionary<string, string>
                {
                    { "scope", "openid profile email offline_access " + service.Resource + "/.default" },
                    { "client_id", service.ClientID.ToString() },
                    { "response_type", "code" },
                    { "redirect_uri", service.RedirectUri },
                    { "client-request-id", requestId.ToString() },
                    { "mscrid", mscrid.ToString() },
                    { "sso_nonce", t.request_nonce },
                });

            var httpClient = HttpClientHelper.GetHttpClient();

            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            request.Headers.Add("x-ms-RefreshTokenCredential", prtToken);
            var response = await httpClient.SendAsync(request);

            return await response.Content.ReadAsStringAsync();
        }

        [SuppressMessage("Naming Rules", "SA1300:Element should begin with upper-case letter", Justification = "Used for deserialization")]
        /// <summary>
        /// Determines if the authorization response contains HTML that should be shown to the user for interactive authentication.
        /// </summary>
        /// <param name="authorizationResponse">The HTML response from the authorization request.</param>
        /// <returns>True if the HTML should be shown to the user, false otherwise.</returns>
        private static bool IsHtmlToBeShownToUser(string authorizationResponse)
        {
            if (string.IsNullOrEmpty(authorizationResponse))
            {
                return false;
            }

            // Check if the response contains HTML
            bool containsHtml = authorizationResponse.Contains("<html") || authorizationResponse.Contains("<!DOCTYPE html");
            if (!containsHtml)
            {
                return false;
            }

            // Check if the response contains automatic redirect scripts
            bool containsAutoRedirect =
                authorizationResponse.Contains("window.location.replace") ||
                authorizationResponse.Contains("window.location.href") ||
                authorizationResponse.Contains("window.location = ") ||
                authorizationResponse.Contains("<meta http-equiv=\"refresh\"");

            // Check if the response contains visible body content
            bool containsVisibleContent =
                authorizationResponse.Contains("<body") &&
                (authorizationResponse.Contains("<h") || // Headers
                authorizationResponse.Contains("<p") || // Paragraphs
                authorizationResponse.Contains("<div") || // Divs
                authorizationResponse.Contains("<span") || // Spans
                authorizationResponse.Contains("<table") || // Tables
                authorizationResponse.Contains("<ul") || // Lists
                authorizationResponse.Contains("<ol") || // Ordered lists
                authorizationResponse.Contains("<img")); // Images

            // Check if the response contains forms or input elements that would require user interaction
            bool containsUserInteractionElements =
                authorizationResponse.Contains("<form") ||
                authorizationResponse.Contains("<input") ||
                authorizationResponse.Contains("<button") ||
                authorizationResponse.Contains("<select") ||
                authorizationResponse.Contains("id=\"loginForm\"") ||
                authorizationResponse.Contains("id=\"credentials\"") ||
                authorizationResponse.Contains("class=\"login\"") ||
                authorizationResponse.Contains("class=\"sign-in\"") ||
                authorizationResponse.Contains("class=\"mfa\"") ||
                authorizationResponse.Contains("multifactor") ||
                authorizationResponse.Contains("verification");

            // If it contains visible content or user interaction elements and doesn't contain auto-redirect,
            // it likely needs to be shown to the user
            return (containsVisibleContent || containsUserInteractionElements) && !containsAutoRedirect;
        }

        private class GetTokenError : JsonSerialization<GetTokenError>
        {
            public string error { get; set; }

            public string error_description { get; set; }

            public string error_uri { get; set; }

            public string correlation_id { get; set; }

            public string trace_id { get; set; }
        }
    }
}
