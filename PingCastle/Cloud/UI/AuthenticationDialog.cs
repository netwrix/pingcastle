namespace PingCastle.Cloud.UI
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading;
    using System.Web;
    using System.Windows.Forms;
    using misc;
    using PingCastle.Cloud.Common;
    using PingCastle.Cloud.Credentials;
    using PingCastle.Cloud.RESTServices.Azure;
    using PingCastle.Cloud.Tokens;
    using PingCastleCommon.Utility;

    /// <summary>
    /// Dialog used for user interactive authentication.
    /// </summary>
    internal partial class AuthenticationDialog : Form
    {
        private AuthenticationDialog()
        {
            InitializeComponent();
            if (NativeMethods.SetQueryNetSessionCount(NativeMethods.SessionOp.SESSION_QUERY) == 0)
            {
                NativeMethods.SetQueryNetSessionCount(NativeMethods.SessionOp.SESSION_INCREMENT);
            }

            webBrowser.Navigating += WebBrowserNavigatingHandler;
            webBrowser.Navigated += WebBrowserNavigatedHandler;
            Trace.WriteLine("Init authentication dialog");
        }

        /// <summary>
        /// Performs Azure authentication and returns an access token.
        /// </summary>
        /// <typeparam name="T">The type of the azure service.</typeparam>
        /// <param name="credential">The credential.</param>
        /// <returns>A new <see cref="Token"/>.</returns>
        /// <exception cref="UnauthorizedAccessException">Thrown when Azure services explicitly deny access.</exception>
        /// <exception cref="PingCastleCloudException">Thrown when authentication fails.</exception>
        /// <exception cref="NotImplementedException">Thrown when authentication returns an empty code.</exception>
        public static Token Authenticate<T>(IAzureCredential credential)
            where T : IAzureService
        {
            AuthenticationResultSet result = default;
            Thread thread = new Thread(
                () =>
                {
                    Trace.WriteLine("Started Thread");
                    var f = new AuthenticationDialog();
                    Trace.WriteLine("AuthenticateInternal");
                    f.AuthenticateInternal<T>(credential, true);
                    Trace.WriteLine("ShowDialog");
                    f.ShowDialog();
                    result = new AuthenticationResultSet
                    {
                        Code = f.code,
                        CodeVerifier = f.codeVerifier,
                        Error = f.error,
                        ErrorDescription = f.error_description,
                    };

                    Trace.WriteLine("code=" + f.code);
                    Trace.WriteLine("error=" + f.error);
                    Trace.WriteLine("error_description=" + f.error_description);
                    Trace.WriteLine("codeVerifier=" + f.codeVerifier);

                    if (!string.IsNullOrEmpty(f.error) && credential.LastTokenQueried != null)
                    {
                        Trace.WriteLine("Error with login hint - retry without");
                        f = new AuthenticationDialog();
                        Trace.WriteLine("AuthenticateInternal");
                        f.AuthenticateInternal<T>(credential, false);
                        Trace.WriteLine("ShowDialog");
                        f.ShowDialog();
                        result = new AuthenticationResultSet
                        {
                            Code = f.code,
                            CodeVerifier = f.codeVerifier,
                            Error = f.error,
                            ErrorDescription = f.error_description,
                        };
                        Trace.WriteLine("code=" + result.Code);
                        Trace.WriteLine("error=" + result.Error);
                        Trace.WriteLine("error_description=" + result.ErrorDescription);
                        Trace.WriteLine("code_verifier=" + result.CodeVerifier);
                    }

                    Trace.WriteLine("Stopped Thread");
                });
            thread.SetApartmentState(ApartmentState.STA); // Set the thread to STA
            Trace.WriteLine("thread.Start");
            thread.Start();
            Trace.WriteLine("thread.Join");
            thread.Join();
            Trace.WriteLine("thread Done");
            if (!result.Error.IsNullOrWhiteSpace())
            {
                throw result.Error switch
                {
                    "access_denied" => new UnauthorizedAccessException("Access denied to " + typeof(T).Name),

                    // Default covers:
                    // invalid_request
                    // unauthorized_client
                    // unsupported_response_type
                    // server_error
                    // temporarily_unavailable
                    // invalid_resource
                    // login_required
                    // interaction_required
                    _ => new PingCastleCloudException(
                        $"Unable to authenticate ({result.Error}) : {result.ErrorDescription}")
                };
            }

            var service = AzureServiceAttribute.GetAzureServiceAttribute<T>();
            if (!result.Code.IsNullOrEmpty())
            {
                var token = TokenFactory.RunGetToken<T>(credential, result.Code, service.RedirectUri, result.CodeVerifier).GetAwaiter().GetResult();
                return Token.LoadFromString(token);
            }

            Trace.WriteLine("No code sent by the dialog");
            throw new NotImplementedException("Unable to authenticate - code is empty");
        }

        private static string GenerateCodeVerifier()
        {
            var buffer = new byte[32];
            using (var randomSource = new RNGCryptoServiceProvider())
            {
                randomSource.GetBytes(buffer);
            }

            return Base64UrlEncoder.EncodeToUrlSafeBase64(buffer);
        }

        /// <summary>
        /// Completes authentication using HTML content that requires user interaction.
        /// </summary>
        /// <typeparam name="T">The type of the Azure service.</typeparam>
        /// <param name="credential">The credential.</param>
        /// <param name="htmlContent">The HTML content to display to the user.</param>
        /// <returns>A new <see cref="Token"/>.</returns>
        /// <exception cref="ApplicationException">Thrown when authentication fails either due to error or no code returned.</exception>
        public static Token CompleteAuthenticationWithHtml<T>(IAzureCredential credential, string htmlContent)
            where T : IAzureService
        {
            AuthenticationResultSet result = default;
            Thread thread = new Thread(() =>
            {
                Trace.WriteLine("Started Thread for HTML authentication");
                var f = new AuthenticationDialog();
                f.service = AzureServiceAttribute.GetAzureServiceAttribute<T>();
                f.codeVerifier = GenerateCodeVerifier();

                Trace.WriteLine("Showing HTML content to user");
                f.webBrowser.DocumentText = htmlContent;
                f.ShowDialog();

                result = new AuthenticationResultSet
                {
                    Code = f.code,
                    CodeVerifier = f.codeVerifier,
                    Error = f.error,
                    ErrorDescription = f.error_description,
                };

                Trace.WriteLine("code=" + f.code);
                Trace.WriteLine("error=" + f.error);
                Trace.WriteLine("error_description=" + f.error_description);
            });

            thread.SetApartmentState(ApartmentState.STA);
            thread.Start();
            thread.Join();

            if (!string.IsNullOrEmpty(result.Error))
            {
                if (result.Error == "access_denied")
                {
                    throw new UnauthorizedAccessException("Access denied: " + result.ErrorDescription);
                }

                throw new ApplicationException(result.Error + ": " + result.ErrorDescription);
            }

            if (string.IsNullOrEmpty(result.Code))
            {
                throw new ApplicationException("No code returned from authentication");
            }

            var service = AzureServiceAttribute.GetAzureServiceAttribute<T>();
            var token = TokenFactory.RunGetToken<T>(credential, result.Code, service.RedirectUri, result.CodeVerifier).Result;
            return Token.LoadFromString(token);
        }

        /// <summary>
        /// Performs continuation of Azure authentication when MFA is required. Returns an access token.
        /// </summary>
        /// <typeparam name="T">The type of the Azure service.</typeparam>
        /// <param name="credential">The credential.</param>
        /// <param name="authUrl">The authentication URL.</param>
        /// <returns>A new <see cref="Token"/>.</returns>
        /// <exception cref="ApplicationException">Thrown when authentication fails either due to error or no code returned.</exception>
        public static Token ContinueAuthentication<T>(IAzureCredential credential, string authUrl)
            where T : IAzureService
        {
            AuthenticationResultSet result = default;

            AuthenticationDialog f = null;
            Thread thread = new Thread(() =>
            {
                Trace.WriteLine("Started MFA continuation Thread");
                f = new AuthenticationDialog();

                f.codeVerifier = GenerateCodeVerifier();
                f.service = AzureServiceAttribute.GetAzureServiceAttribute<T>();

                // Navigate to the authentication URL instead of setting DocumentText
                // This preserves cookies and session state
                Trace.WriteLine("Navigating to auth URL for MFA");
                f.webBrowser.Navigate(authUrl);

                Trace.WriteLine("Showing MFA dialog");
                f.ShowDialog();

                result = new AuthenticationResultSet
                {
                    Code = f.code,
                    CodeVerifier = f.codeVerifier,
                    Error = f.error,
                    ErrorDescription = f.error_description,
                };

                Trace.WriteLine("code=" + result.Code);
                Trace.WriteLine("error=" + result.Error);
                Trace.WriteLine("error_description=" + result.ErrorDescription);
                Trace.WriteLine("code_verifier=" + result.CodeVerifier);
            });

            thread.SetApartmentState(ApartmentState.STA);
            thread.Start();
            thread.Join();

            if (!string.IsNullOrEmpty(result.Error))
            {
                throw new ApplicationException($"Authentication error: {result.Error}. {result.ErrorDescription}");
            }

            if (string.IsNullOrEmpty(result.Code))
            {
                throw new ApplicationException("No authorization code was obtained.");
            }

            var tokenTask = TokenFactory.RunGetToken<T>(
                credential,
                result.Code,
                f?.service?.RedirectUri,
                result.CodeVerifier);

            tokenTask.Wait();
            return Token.LoadFromString(tokenTask.Result);
        }

        private string codeVerifier;

        private void AuthenticateInternal<T>(IAzureCredential credential, bool useLoginHint)
            where T : IAzureService
        {
            Trace.WriteLine($"Authenticate internal - useLoginHint= {useLoginHint}");
            codeVerifier = GenerateCodeVerifier();
            string state = Guid.NewGuid().ToString() + Guid.NewGuid();

            service = AzureServiceAttribute.GetAzureServiceAttribute<T>();

            // https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow
            var info = new Dictionary<string, string>
            {
                    { "resource", service.Resource },
                    { "client_id", service.ClientID.ToString() },
                    { "response_type", "code" },
                    { "redirect_uri", service.RedirectUri },
                    { "code_challenge_method", "S256" },
                    { "code_challenge", Base64UrlEncoder.CreateBase64UrlEncodedSha256Hash(codeVerifier) },
                    { "state", state },
                    { "response_mode", "fragment" },
                    { "client-request-id", Guid.NewGuid().ToString() },
                    { "prompt", "select_account" },
                    { "msafed", "0" }, // azureAD only
            };

            if (useLoginHint && credential.LastTokenQueried != null)
            {
                Trace.WriteLine("LastTokenQueried");
                var jwt = credential.LastTokenQueried.ToJwtToken();
                info.Add("domain_hint", jwt.tid);
                info.Add("login_hint", jwt.unique_name);
                info["prompt"] = "none";

                WindowState = FormWindowState.Minimized;
                timerForAutoSignAttempt.Interval = 1000;
                timerForAutoSignAttempt.Start();
            }

            string aep = Constants.OAuth2AuthorizeEndPoint;
            if (!string.IsNullOrEmpty(credential.TenantidToQuery))
            {
                aep = aep.Replace("common", credential.TenantidToQuery);
            }

            string uri = HttpClientHelper.BuildUri(aep, info);
            Trace.WriteLine("Uri: " + uri);
            webBrowser.Navigate(uri);
            Trace.WriteLine("Done navigate url");
        }

        private int logSessionId;

        private async void WebBrowserNavigatingHandler(object sender, WebBrowserNavigatingEventArgs e)
        {
            Trace.WriteLine("Navigating to:" + e.Url);
            logSessionId = await HttpClientHelper.LogNavigatingAsync(e.Url);
            if (CheckFinalPage(e.Url))
            {
                Trace.WriteLine("Navigating: Final page");
                e.Cancel = true;
            }

            if (CheckErrorPage(e.Url))
            {
                Trace.WriteLine("Error page");
                e.Cancel = true;
            }
        }

        private async void WebBrowserNavigatedHandler(object sender, WebBrowserNavigatedEventArgs e)
        {
            Trace.WriteLine($"Navigated to: {e.Url}");
            await HttpClientHelper.LogNavigatedAsync(logSessionId, e.Url, webBrowser.DocumentText);
            if (CheckFinalPage(e.Url))
            {
                Trace.WriteLine("Final page");
            }

            if (CheckErrorPage(e.Url))
            {
                Trace.WriteLine("Error page");
            }
        }

        private string code = null;
        private string error = null;
        private string error_description = null;
        private AzureServiceAttribute service;

        private bool CheckErrorPage(Uri url)
        {
            if (url.Scheme != "res")
            {
                return false;
            }

            Trace.WriteLine("FullUrl:" + url);
            Trace.WriteLine("Error:" + url.LocalPath);
            error = url.LocalPath;
            if (string.IsNullOrEmpty(error))
            {
                error = url.ToString();
            }

            Trace.WriteLine("Stop");
            webBrowser.Stop();

            this.Close();
            Trace.WriteLine("Closed");
            return true;
        }

        private bool CheckFinalPage(Uri url)
        {
            if (service == null)
            {
                return false;
            }

            Uri stopUri = new Uri(service.RedirectUri);
            if (url.Authority == stopUri.Authority && url.AbsolutePath == stopUri.AbsolutePath)
            {
                Trace.WriteLine("Final page detected");
                if (string.IsNullOrEmpty(url.Fragment))
                {
                    Trace.WriteLine("No url fragment");
                    throw new NotImplementedException();
                }

                var nv = HttpUtility.ParseQueryString(url.Fragment.Substring(1));
                code = null;
                foreach (string key in nv)
                {
                    Trace.WriteLine("key:" + key);
                    Trace.WriteLine("value:" + nv[key]);
                    switch (key)
                    {
                        case "error":
                            error = nv[key];
                            break;
                        case "error_description":
                            error_description = nv[key];
                            break;
                        case "code":
                            code = nv[key];
                            break;
                        default:
                            Trace.WriteLine("nativeClient value " + key + ": " + nv[key]);
                            break;
                    }
                }

                Trace.WriteLine("Stop");
                webBrowser.Stop();

                this.Close();
                Trace.WriteLine("Closed");
                return true;
            }

            return false;
        }

        private void TimerForAutoSignAttempt_Tick(object sender, EventArgs e)
        {
            timerForAutoSignAttempt.Stop();
            this.WindowState = FormWindowState.Normal;
        }

        private struct AuthenticationResultSet
        {
            public string Code { get; set; }

            public string CodeVerifier { get; set; }

            public string Error { get; set; }

            public string ErrorDescription { get; set; }
        }

        private static class NativeMethods
        {
            internal enum SessionOp
            {
                SESSION_QUERY,
                SESSION_INCREMENT,
                SESSION_DECREMENT,
            }

            [DllImport("IEFRAME.dll", CallingConvention = CallingConvention.StdCall, ExactSpelling = true)]
            internal static extern int SetQueryNetSessionCount(SessionOp sessionOp);
        }
    }
}
