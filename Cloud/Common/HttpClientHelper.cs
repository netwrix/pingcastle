//
// Copyright (c) Vincent LE TOUX for Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Cloud.Logs;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.ServiceModel.Channels;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace PingCastle.Cloud.Common
{
    public class HttpClientHelper
    {
        public static string BuildUri(string rootUri, IEnumerable<KeyValuePair<string, string>> optionalQueryItems)
        {
            var builder = new UriBuilder(rootUri);
            builder.Port = -1;
            if (optionalQueryItems != null)
            {
                var query = HttpUtility.ParseQueryString(builder.Query);
                foreach (var item in optionalQueryItems)
                {
                    query[item.Key] = item.Value;
                }
                builder.Query = query.ToString();
            }
            return builder.ToString();
        }

        public static void EnableLoging(SazGenerator generator)
        {
            if (_generator != null)
            {
                _generator.Dispose();
            }
            _generator = generator;
            if (_cachedHttpClient != null)
            {
                _cachedHttpClient.Dispose();
                _cachedHttpClient = null;
            }
        }
        static SazGenerator _generator;

        public static async Task<int> LogNavigatingAsync(Uri url)
        {
            if (_generator == null)
                return 0;
            if (url.Scheme == "res")
                url = new Uri(url.ToString().Replace("res://", "http://"));
            if (url.Scheme != "http" && url.Scheme != "https")
                return 0;
            return await _generator.RecordBeginQueryAsync(new HttpRequestMessage(HttpMethod.Get, url));
        }

        public static async Task LogNavigatedAsync(int logSessionId, Uri url, string documentText)
        {
            if (_generator == null)
                return;
            if (url.Scheme == "res")
                url = new Uri(url.ToString().Replace("res://", "http://"));
            if (url.Scheme != "http" && url.Scheme != "https")
                return;

            using (var ms = new MemoryStream())
            {
                var b = Encoding.UTF8.GetBytes(documentText);
                ms.Write(b, 0, b.Length);
                ms.Position = 0;

                var result = new HttpResponseMessage();
                result.Content = new StreamContent(ms);
                await _generator.RecordEndQueryAsync(logSessionId, result);
            }

        }

        public static async Task<int> LogSoapBeginAsync(Message request)
        {
            if (_generator == null)
                return 0;

            HttpRequestMessageProperty prop = null;
            if (request.Properties.ContainsKey("httpRequest"))
            {
                prop = (HttpRequestMessageProperty)request.Properties["httpRequest"];
            }
            var m = HttpMethod.Get;
            if (prop != null && string.Equals(prop.Method, "post", StringComparison.OrdinalIgnoreCase))
                m = HttpMethod.Post;
            var r = new HttpRequestMessage(m, request.Headers.Action);
            using (var ms = new MemoryStream())
            {
                var b = Encoding.UTF8.GetBytes(request.ToString());
                ms.Write(b, 0, b.Length);
                ms.Position = 0;

                r.Content = new StreamContent(ms);

                return await _generator.RecordBeginQueryAsync(r);
            }
        }

        public static async Task LogSoapEndAsync(int logSessionId, Message request)
        {
            if (_generator == null)
                return;

            using (var ms = new MemoryStream())
            {
                var b = Encoding.UTF8.GetBytes(request.ToString());
                ms.Write(b, 0, b.Length);
                ms.Position = 0;

                var result = new HttpResponseMessage();
                result.Content = new StreamContent(ms);
                await _generator.RecordEndQueryAsync(logSessionId, result);
            }

        }

        public static string LogComment
        {
            get
            {
                if (_generator != null)
                    return _generator.SessionComment;
                return null;
            }
            set
            {
                if (_generator != null)
                    _generator.SessionComment = value;
            }
        }

        private static HttpClient _cachedHttpClient;
        public static HttpClient GetHttpClient()
        {
            if (_cachedHttpClient != null)
                return _cachedHttpClient;

            HttpMessageHandler handler = new HttpClientHandler()
            {
                AllowAutoRedirect = false
            };

            if (_generator != null)
            {
                handler = new LoggingHandler(_generator, handler);
            }

            HttpClient client = new HttpClient(handler);
            client.DefaultRequestHeaders.Accept.Clear();
            _cachedHttpClient = client;

            return _cachedHttpClient;
        }
    }
}
