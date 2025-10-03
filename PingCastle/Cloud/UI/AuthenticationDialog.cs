//
// Copyright (c) Vincent LE TOUX for Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Cloud.Common;
using PingCastle.Cloud.Credentials;
using PingCastle.Cloud.RESTServices.Azure;
using PingCastle.Cloud.Tokens;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web;
using System.Windows.Forms;

namespace PingCastle.Cloud.UI
{
    internal partial class AuthenticationDialog : Form
    {
        [DllImport("urlmon.dll", ExactSpelling = true)]
        internal static extern int CoInternetSetFeatureEnabled(int featureEntry, int dwFlags, bool fEnable);

        public AuthenticationDialog()
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

        public static Token Authenticate<T>(IAzureCredential credential) where T : IAzureService
        {
            string code = null, codeVerifier = null, error = null, error_description = null;
            string token;
            Thread thread = new Thread(
                () =>
                {
                    Trace.WriteLine("Started Thread");
                    var f = new AuthenticationDialog();
                    Trace.WriteLine("AuthenticateInternal");
                    f.AuthenticateInternal<T>(credential, true);
                    Trace.WriteLine("ShowDialog");
                    f.ShowDialog();
                    code = f.code;
                    error = f.error;
                    error_description = f.error_description;
                    codeVerifier = f.codeVerifier;
                    Trace.WriteLine("code=" + code);
                    Trace.WriteLine("error=" + error);
                    Trace.WriteLine("error_description=" + error_description);
                    Trace.WriteLine("codeVerifier=" + codeVerifier);

                    if (!string.IsNullOrEmpty(f.error) && credential.LastTokenQueried != null)
                    {
                        Trace.WriteLine("Error with login hint - retry without");
                        f = new AuthenticationDialog();
                        Trace.WriteLine("AuthenticateInternal");
                        f.AuthenticateInternal<T>(credential, false);
                        Trace.WriteLine("ShowDialog");
                        f.ShowDialog();
                        code = f.code;
                        error = f.error;
                        error_description = f.error_description;
                        codeVerifier = f.codeVerifier;
                        Trace.WriteLine("code=" + code);
                        Trace.WriteLine("error=" + error);
                        Trace.WriteLine("error_description=" + error_description);
                        Trace.WriteLine("codeVerifier=" + codeVerifier);
                    }
                    
                    Trace.WriteLine("Stopped Thread");
                });
            thread.SetApartmentState(ApartmentState.STA); //Set the thread to STA
            Trace.WriteLine("thread.Start");
            thread.Start();
            Trace.WriteLine("thread.Join");
            thread.Join();
            Trace.WriteLine("thread Done");
            if (!string.IsNullOrEmpty(error))
            {
                switch (error)
                {
                    case "access_denied":
                        throw new UnauthorizedAccessException("Access denied to " + typeof(T).Name);
                    case "invalid_request":
                    case "unauthorized_client":
                    case "unsupported_response_type":
                    case "server_error":
                    case "temporarily_unavailable":
                    case "invalid_resource":
                    case "login_required":
                    case "interaction_required":
                    default:
                        throw new PingCastleCloudException("Unable to authenticate (" + error + ") : " + error_description);

                }
            }
            var endpoint = EndPointAttribute.GetEndPointAttribute<T>();
            var service = AzureServiceAttribute.GetAzureServiceAttribute<T>();
            if (!string.IsNullOrEmpty(code))
            {
                token = TokenFactory.RunGetToken<T>(credential, code, service.RedirectUri, codeVerifier).GetAwaiter().GetResult();
                return Token.LoadFromString(token);
            }
            Trace.WriteLine("No code sent by the dialog");
            throw new NotImplementedException("Unable to authenticate - code is empty");
        }

        static public byte[] CreateSha256HashBytes(string input)
        {
            using (SHA256Cng sha = new SHA256Cng())
            {
                return sha.ComputeHash(Encoding.UTF8.GetBytes(input));
            }
        }

        internal static string Encode(byte[] arg)
        {
            if (arg == null)
            {
                return null;
            }
            return Convert.ToBase64String(arg).Split('=')[0].Replace('+', '-').Replace('/', '_');
        }

        static public string GenerateCodeVerifier()
        {
            byte[] buffer = new byte[32];
            using (RNGCryptoServiceProvider randomSource = new RNGCryptoServiceProvider())
            {
                randomSource.GetBytes(buffer);
            }
            return Encode(buffer);
        }

        static public string CreateBase64UrlEncodedSha256Hash(string input)
        {
            if (!string.IsNullOrEmpty(input))
            {
                return Encode(CreateSha256HashBytes(input));
            }
            return null;
        }

        string codeVerifier;
        void AuthenticateInternal<T>(IAzureCredential credential, bool use_login_hint) where T : IAzureService
        {
            Trace.WriteLine("Authenticate internal - use_login_hint=" + use_login_hint);
            codeVerifier = GenerateCodeVerifier();
            string state = Guid.NewGuid().ToString() + Guid.NewGuid().ToString();

            service = AzureServiceAttribute.GetAzureServiceAttribute<T>();

            endpoint = EndPointAttribute.GetEndPointAttribute<T>();

            //https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow
            var info = new Dictionary<string, string> {
                    { "resource", service.Resource } ,
                    { "client_id", service.ClientID.ToString()},
                    { "response_type", "code" },
                    { "redirect_uri", service.RedirectUri},
                    { "code_challenge_method", "S256"},
                    { "code_challenge", CreateBase64UrlEncodedSha256Hash(codeVerifier)},
                    { "state", state},
                    { "response_mode", "fragment"},
                    { "client-request-id", Guid.NewGuid().ToString()},
                    { "prompt", "select_account"},
                    { "msafed", "0"}, //azureAD only
                };


            if (use_login_hint && credential.LastTokenQueried != null)
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
            Trace.WriteLine("Uri A: " + uri);
            webBrowser.Navigate(uri);
            Trace.WriteLine("Done navigate url a");
        }

        int logSessionId;
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
            Trace.WriteLine("Navigated to:" + e.Url);
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

        protected string code = null;
        protected string error = null;
        protected string error_description = null;
        private AzureServiceAttribute service;
        private EndPointAttribute endpoint;

        bool CheckErrorPage(Uri Url)
        {
            if (Url.Scheme == "res")
            {
                Trace.WriteLine("FullUrl:" + Url);
                Trace.WriteLine("Error:" + Url.LocalPath);
                error = Url.LocalPath;
                if (string.IsNullOrEmpty(error))
                {
                    error = Url.ToString();
                }
                Trace.WriteLine("Stop");
                webBrowser.Stop();

                this.Close();
                Trace.WriteLine("Closed");
                return true;
            }
            return false;
        }

        bool CheckFinalPage(Uri Url)
        {
            if (service == null)
                return false;
            Uri stopUri = new Uri(service.RedirectUri);
            if (Url.Authority == stopUri.Authority && Url.AbsolutePath == stopUri.AbsolutePath)
            {
                Trace.WriteLine("Final page detected");
                if (string.IsNullOrEmpty(Url.Fragment))
                {
                    Trace.WriteLine("No url fragment");
                    throw new NotImplementedException();
                }
                var nv = HttpUtility.ParseQueryString(Url.Fragment.Substring(1));
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

        internal static class NativeMethods
        {
            internal enum SessionOp
            {
                SESSION_QUERY,
                SESSION_INCREMENT,
                SESSION_DECREMENT
            }

            [DllImport("IEFRAME.dll", CallingConvention = CallingConvention.StdCall, ExactSpelling = true)]
            internal static extern int SetQueryNetSessionCount(SessionOp sessionOp);
        }

        private void timerForAutoSignAttempt_Tick(object sender, EventArgs e)
        {
            timerForAutoSignAttempt.Stop();
            this.WindowState = FormWindowState.Normal;
        }
    }
}
