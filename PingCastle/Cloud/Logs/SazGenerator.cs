//
// Copyright (c) Vincent LE TOUX for Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Packaging;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Serialization;

namespace PingCastle.Cloud.Logs
{
    public class SazGenerator : IDisposable
    {
        private static readonly SemaphoreSlim semaphore = new SemaphoreSlim(1, 1);
        public SazGenerator() : this("log.saz")
        {

        }
        public SazGenerator(string filename)
        {
            CreateFile(filename);
        }

        Package archive;
        Dictionary<int, sazentry> entries = new Dictionary<int, sazentry>();

        int entryNum = 1;

        public string SessionComment { get; set; }

        class sazentry
        {
            public Uri uri { get; set; }
            public DateTime StartTime { get; internal set; }
        }

        private void CreateFile(string filename)
        {
            archive = Package.Open(filename,
                System.IO.FileMode.Create,
                System.IO.FileAccess.ReadWrite);

            PackagePart indexPackagePart = archive.CreatePart(new Uri("/_index.htm", UriKind.Relative), "text/html");
        }

        private static Uri UriForPart(int sessionId, char mode)
        {
            return new Uri(string.Format("/raw/{0}_{1}.{2}", sessionId, mode, (mode == 'm') ? "xml" : "txt"), UriKind.Relative);
        }

        // called from multiple threads
        public async Task<int> RecordBeginQueryAsync(HttpRequestMessage request)
        {
            await  semaphore.WaitAsync();

            try
            {
                entries.Add(entryNum, new sazentry { uri = request.RequestUri, StartTime = DateTime.Now });

                var requestPart = archive.CreatePart(UriForPart(entryNum, 'c'), "text/plain");
                using (var requestStream = requestPart.GetStream(FileMode.Create))
                {
                    var b = RequestMessageToString(request);
                    requestStream.Write(b, 0, b.Length);
                    if (request.Content != null)
                    {
                        await request.Content.CopyToAsync(requestStream);
                    }
                }

                return entryNum++;
            }
            finally
            {
                semaphore.Release();
            }
        }

        // called from multiple threads
        public async Task RecordEndQueryAsync(int sessionId, HttpResponseMessage response)
        {
            //copy the response stream to a stream which can be rewinded
            var originalContent = response.Content;

            var ms = new MemoryStream();
            await response.Content.CopyToAsync(ms);
            ms.Position = 0;

            var newContent = new StreamContent(ms);
            foreach (var header in originalContent.Headers)
            {
                newContent.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }
            response.Content = newContent;
            
            await semaphore.WaitAsync();

            try
            {
                entries.TryGetValue(sessionId, out var entry);

                TimeSpan duration = DateTimeOffset.UtcNow.Subtract(entry.StartTime);

                var responsePart = archive.CreatePart(UriForPart(sessionId, 's'), "text/plain");

                using (var responseStream = responsePart.GetStream(FileMode.Create))
                {
                    var b = ResponseMessageToString(response);
                    responseStream.Write(b, 0, b.Length);
                    if (response.Content != null)
                    {
                        await response.Content.CopyToAsync(responseStream);
                    }
                }

                var metadataPart = archive.CreatePart(UriForPart(sessionId, 'm'), "application/xml");
                var metadata = CreateMetadataForSession(sessionId, entry.StartTime, duration);
                using (var metadataStream = metadataPart.GetStream(FileMode.Create))
                {
                    metadata.WriteToStream(metadataStream);
                }
            }
            finally
            {
                semaphore.Release();
            }
        }

        byte[] RequestMessageToString(HttpRequestMessage request)
        {
            var sb = new StringBuilder();
            SerializeRequestLine(sb, request);
            SerializeHeaderFields(sb, request.Headers);
            if (request.Content != null)
            {
                SerializeHeaderFields(sb, request.Content.Headers);
            }
            sb.Append("\r\n");
            return Encoding.UTF8.GetBytes(sb.ToString());
        }


        byte[] ResponseMessageToString(HttpResponseMessage response)
        {
            var sb = new StringBuilder();
            SerializeStatusLine(sb, response);
            SerializeHeaderFields(sb, response.Headers);
            if (response.Content != null)
            {
                SerializeHeaderFields(sb, response.Content.Headers);
            }
            sb.Append("\r\n");
            return Encoding.UTF8.GetBytes(sb.ToString());
        }

        private static void SerializeRequestLine(StringBuilder message, HttpRequestMessage httpRequest)
        {
            message.Append(httpRequest.Method + " ");
            message.Append(httpRequest.RequestUri.PathAndQuery + " ");
            message.Append("HTTP/" + ((httpRequest.Version != null) ? httpRequest.Version.ToString(2) : "1.1") + "\r\n");
            if (httpRequest.Headers.Host == null)
            {
                message.Append("Host: " + httpRequest.RequestUri.Authority + "\r\n");
            }
        }

        private static void SerializeHeaderFields(StringBuilder message, HttpHeaders headers)
        {
            if (headers != null)
            {
                foreach (KeyValuePair<string, IEnumerable<string>> header in headers)
                {
                    message.Append(header.Key + ": " + string.Join(", ", header.Value) + "\r\n");
                }
            }
        }
        private static void SerializeStatusLine(StringBuilder message, HttpResponseMessage httpResponse)
        {
            message.Append("HTTP/" + ((httpResponse.Version != null) ? httpResponse.Version.ToString(2) : "1.1") + " ");
            message.Append((int)httpResponse.StatusCode + " ");
            message.Append(httpResponse.ReasonPhrase + "\r\n");
        }


        private SessionMetadata CreateMetadataForSession(int sessionId, DateTimeOffset startTime, TimeSpan duration)
        {
            var metadata = new SessionMetadata
            {
                SessionID = sessionId,
                BitFlags = 59
            };

            metadata.PipeInfo = new PipeInfo { Streamed = true, Reused = false, CltReuse = false };
            const string format = @"yyyy-MM-ddTHH\:mm\:ss.fffffffzzz";
            metadata.SessionTimers = new SessionTimers
            {
                ClientConnected = startTime.ToString(format),
                ClientBeginRequest = startTime.ToString(format),
                GotRequestHeaders = startTime.ToString(format),
                ClientDoneRequest = startTime.ToString(format),
                ServerConnected = startTime.ToString(format),
                FiddlerBeginRequest = startTime.ToString(format),
                ServerGotRequest = startTime.ToString(format),
                ServerBeginResponse = startTime.Add(duration).ToString(format),
                GotResponseHeaders = startTime.Add(duration).ToString(format),
                ServerDoneResponse = startTime.Add(duration).ToString(format),
                ClientBeginResponse = startTime.Add(duration).ToString(format),
                ClientDoneResponse = startTime.Add(duration).ToString(format)
            };

            metadata.SessionFlags.Add(new SessionFlag { Name = SessionFlag.ClientIP, Value = "127.0.0.1" });
            metadata.SessionFlags.Add(new SessionFlag { Name = SessionFlag.ProcessInfo, Value = "pingcastlecloud.exe:1234" });
            if (!string.IsNullOrEmpty(SessionComment))
            {
                metadata.SessionFlags.Add(new SessionFlag { Name = SessionFlag.Comment, Value = SessionComment });
            }
            return metadata;
        }


        void CloseFile()
        {
            archive.Close();
            archive = null;
        }

        // Other functions go here...

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                // free managed resources
                CloseFile();
            }
            // free native resources if there are any.
        }

        [XmlRoot("Session")]
        public class SessionMetadata
        {
            public SessionMetadata()
            {
                this.SessionFlags = new List<SessionFlag>();
            }

            [XmlAttribute("SID")]
            public int SessionID { get; set; }

            [XmlAttribute]
            public int BitFlags { get; set; }

            [XmlElement]
            public SessionTimers SessionTimers { get; set; }

            [XmlElement]
            public PipeInfo PipeInfo { get; set; }

            [XmlArray("SessionFlags")]
            public List<SessionFlag> SessionFlags { get; set; }

            internal void WriteToStream(Stream metadataStream)
            {
                XmlSerializer serialize = new XmlSerializer(this.GetType());
                serialize.Serialize(metadataStream, this);
            }
        }

        public class PipeInfo
        {
            [XmlAttribute("Streamed")]
            public bool Streamed
            {
                get; set;
            }

            [XmlAttribute("CltReuse")]
            public bool CltReuse
            {
                get; set;
            }

            [XmlAttribute("Reused")]
            public bool Reused { get; set; }
        }

        public class SessionFlag
        {
            [XmlAttribute("N")]
            public string Name { get; set; }

            [XmlAttribute("V")]
            public string Value { get; set; }

            public const string EgressPort = "x-egressport";
            public const string ResponseBodyTransferLength = "x-responsebodytransferlength";
            public const string ClientPort = "x-clientport";
            public const string ClientIP = "x-clientip";
            public const string ServerSocket = "x-serversocket";
            public const string HostIP = "x-hostip";
            public const string ProcessInfo = "x-processinfo";
            public const string Comment = "ui-comments";

        }

        public class SessionTimers
        {
            [XmlAttribute]
            public string ClientConnected { get; set; }

            [XmlAttribute]
            public string ClientBeginRequest { get; set; }

            [XmlAttribute]
            public string GotRequestHeaders { get; set; }

            [XmlAttribute]
            public string ClientDoneRequest { get; set; }

            [XmlAttribute]
            public int GatewayTime { get; set; }

            [XmlAttribute]
            public int DNSTime { get; set; }

            [XmlAttribute]
            public int TCPConnectTime { get; set; }

            [XmlAttribute]
            public int HTTPSHandshakeTime { get; set; }

            [XmlAttribute]
            public string ServerConnected { get; set; }

            [XmlAttribute]
            public string FiddlerBeginRequest { get; set; }

            [XmlAttribute]
            public string ServerGotRequest { get; set; }

            [XmlAttribute]
            public string ServerBeginResponse { get; set; }

            [XmlAttribute]
            public string GotResponseHeaders { get; set; }

            [XmlAttribute]
            public string ServerDoneResponse { get; set; }

            [XmlAttribute]
            public string ClientBeginResponse { get; set; }

            [XmlAttribute]
            public string ClientDoneResponse { get; set; }

        }
    }
}
