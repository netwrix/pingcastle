using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;

namespace PingCastle.misc
{

    class ConnectionTesterHttp : ConnectionTester
    {

        List<string> ExecQuery(Uri uri, byte[] ChallengeResponse, StreamWriter sw, StreamReader sr)
        {
            var pqr = string.Format("GET {0}  HTTP/1.1\r\nHost: {1}\r\n", uri.PathAndQuery, uri.Host);
            if (ChallengeResponse != null)
            {
                pqr += string.Format("Authorization: {0} {1}\r\n", package, Convert.ToBase64String(ChallengeResponse));
            }

            sw.WriteLine(pqr);
            sw.Flush();

            var output = new List<string>();
            string answer = sr.ReadLine();
            while (!string.IsNullOrEmpty(answer))
            {
                output.Add(answer);
                answer = sr.ReadLine();
            }
            return output;
        }

        protected override ConnectionTesterStatus SendPackets(Stream stream, Uri uri)
        {

            using (var sw = new StreamWriter(stream))
            using (var sr = new StreamReader(stream))
            {

                byte[] Response = null;
                for (int i = 0; i < 20; i++)
                {
                    var ChallengeResponse = GetOutgoingBlob(Response);

                    var headers = ExecQuery(uri, ChallengeResponse, sw, sr);

                    if (headers.Count < 1)
                    {
                        Trace.WriteLine("No headers returned");
                        return ConnectionTesterStatus.InternalError;
                    }

                    if (headers[0].EndsWith("200 OK"))
                    {
                        if (i == 0)
                            return ConnectionTesterStatus.NoAuthenticationNeeded;
                        return ConnectionTesterStatus.AuthenticationSuccessfull;
                    }

                    if (!headers[0].EndsWith("401 Unauthorized"))
                    {
                        Trace.WriteLine("Header returned: " + headers[0]);
                        return ConnectionTesterStatus.InternalError;
                    }

                    var cl = GetContentLength(headers);
                    if (cl > 0)
                    {
                        var b = new char[cl];
                        sr.ReadBlock(b, 0, b.Length);
                    }

                    Response = GetAuthenticationRequest(headers, package);
                    if (Response == null)
                    {
                        if (i == 0 && headers.Contains("WWW-Authenticate: NTLM"))
                        {
                            Trace.WriteLine("Reinit to NTLM");
                            package = "NTLM";
                            Reinit();
                        }
                        else
                        {
                            return ConnectionTesterStatus.AuthenticationFailure;
                        }
                    }
                }


                return ConnectionTesterStatus.AuthenticationFailure;

            }
        }

        private static byte[] GetAuthenticationRequest(List<string> headers, string package)
        {
            foreach (var h in headers)
            {
                string c = "WWW-Authenticate: " + package + " ";
                if (h.StartsWith(c))
                {
                    return Convert.FromBase64String(h.Substring(c.Length));
                }
            }

            return null;
        }

        private static int GetContentLength(List<string> headers)
        {
            foreach (var h in headers)
            {
                if (h.StartsWith("Content-Length: "))
                {
                    return int.Parse(h.Substring(16));
                }
            }

            return 0;
        }
    }

}
