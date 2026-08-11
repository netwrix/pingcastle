//
// Copyright (c) Vincent LE TOUX for Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Cloud.Common;
using PingCastle.Cloud.Credentials;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace PingCastle.Cloud.RESTServices.Azure
{
    public abstract class RESTClientBase<API> where API: IAzureService
    {
        protected IAzureCredential credential;
        protected RESTClientBase(IAzureCredential credential)
        {
            this.credential = credential;
        }

        protected U CallEndPoint<T, U>(string function, T input)
        {
            return CallEndPointAsync<T, U>(function, input).GetAwaiter().GetResult();
        }

        protected U CallEndPoint<U>(string function, string optionalQuery = "")
        {
            return CallEndPointAsync<object, U>(function, null, optionalQuery).GetAwaiter().GetResult();
        }

        public class Response<T> : JsonSerialization<Response<T>>
        {
            [JsonPropertyName("odata.metadata")]
            public string OdataMetadata { get; set; }

            [JsonPropertyName("odata.nextLink")]
            public string OdataNextLink { get; set; }

            [JsonPropertyName("@odata.nextLink")]
            public string OdataNextLink2 { get { return OdataNextLink; } set { OdataNextLink = value; } }
            public List<T> value { get; set; }
        }

        public class JsonErrorMessage
        {
            public string lang { get; set; }
            public string value { get; set; }
        }

        public class JsonErrorOdataError
        {
            public string code { get; set; }
            public JsonErrorMessage message { get; set; }
            public string requestId { get; set; }
            public DateTime date { get; set; }
        }

        public class JsonError : JsonSerialization<JsonError>
        {
            [JsonPropertyName("odata.error")]
            public JsonErrorOdataError OdataError { get; set; }
        }

        public List<U> CallEndPointWithPagging<T, U>(string function, T input = default(T), string optionalQuery = "")
        {
            return CallEndPointWithPaggingAsync<T, U>(function, input, optionalQuery).GetAwaiter().GetResult();
        }

        public List<U> CallEndPointWithPagging<U>(string function,string optionalQuery = "")
        {
            return CallEndPointWithPaggingAsync<object, U>(function, null, optionalQuery).GetAwaiter().GetResult();
        }

        public async Task<List<U>> CallEndPointWithPaggingAsync<T, U>(string function, T input, string optionalQuery = "")
        {

            var r = await CallEndPointAsync<T, Response<U>>(function, input, optionalQuery);
            var output = new List<U>();
            output.AddRange(r.value);

            while (!string.IsNullOrEmpty(r.OdataNextLink))
            {
                var builder = new UriBuilder(r.OdataNextLink);
                r = await CallEndPointAsync<T, Response<U>>(function, input, builder.Query);
                output.AddRange(r.value);
            }

            return output;
        }

        public async Task CallEndPointWithPaggingAndActionAsync<T, U>(string function, T input, Action<U> action, string optionalQuery = "")
        {

            var r = await CallEndPointAsync<T, Response<U>>(function, input, optionalQuery);
            foreach(var a in r.value)
            {
                action(a);
            }
            while (!string.IsNullOrEmpty(r.OdataNextLink))
            {
                var builder = new UriBuilder(r.OdataNextLink);
                r = await CallEndPointAsync<T, Response<U>>(function, input, builder.Query);
                foreach (var a in r.value)
                {
                    action(a);
                }
            }
        }

        protected async Task<U> CallEndPointAsync<T, U>(string function, T input, string optionalQuery = "")
        {
            var token = await credential.GetToken<API>();

            var httpClient = HttpClientHelper.GetHttpClient() ?? new HttpClient();
            var requestUri = BuidEndPoint(function, optionalQuery);
            Trace.WriteLine("Calling " + requestUri);
            using (var request = new HttpRequestMessage(input == null ? HttpMethod.Get : HttpMethod.Post, requestUri))
            {
                request.Headers.Add("Authorization", "Bearer " + token.access_token);
                request.Headers.Add("x-ms-client-request-id", Guid.NewGuid().ToString());
                if (input != null)
                {
                    var jsonInput = JsonSerializer.Serialize(input);
                    request.Content = new StringContent(jsonInput, Encoding.UTF8, "application/json");
                }

                var response = await httpClient.SendAsync(request);
                if (!response.IsSuccessStatusCode)
                {
                    Trace.WriteLine("ErrorCode: " + response.StatusCode);
                    var jsonError = await response.Content.ReadAsStringAsync();
                    Trace.WriteLine("Error: " + jsonError);
                    JsonError error = null;
                    try
                    {
                        error = JsonSerializer.Deserialize<JsonError>(jsonError);
                    }
                    catch
                    {

                    }
                    if (error != null && error.OdataError != null && error.OdataError.message != null)
                    {
                        throw new ApplicationException("Error when calling " + requestUri + " : " + error.OdataError.message.value);
                    }
                    // default error handling
                    response.EnsureSuccessStatusCode();
                }

                var jsonOuput = await response.Content.ReadAsStringAsync();
                return JsonSerializer.Deserialize<U>(jsonOuput);
            }
        }

        virtual protected string BuidEndPoint(string function, string optionalQuery)
        {
            throw new NotImplementedException();
        }
    }
}
