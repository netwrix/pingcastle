using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Authentication;
using System.Security.Authentication.ExtendedProtection;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace PingCastle.misc
{
    public enum ConnectionTesterStatus
    {
        InvalidData,
        InitializationFailed,
        NoAuthenticationNeeded,
        AuthenticationFailure,
        InternalError,
        ChannelBindingEnabled,
        ChannelBindingDisabled,
        SignatureRequired,
        SignatureNotRequired,
        AuthenticationSuccessfull,
        LocalCall
    }

    abstract class ConnectionTester
    {

        public static ConnectionTesterStatus TestExtendedAuthentication(Uri uri, NetworkCredential credential)
        {
            try
            {
                var tester = CreateTester(uri);
                tester.Credential = credential;
                return tester.TestExtendedAuthentication(uri);
            }
            catch (LocalCallException)
            {
                return ConnectionTesterStatus.LocalCall;
            }
            catch (Exception ex)
            {
                Trace.WriteLine("Exception: " + ex.Message);
                Trace.WriteLine("StackTrace: " + ex.StackTrace);
                return ConnectionTesterStatus.InvalidData;
            }
        }

        public static ConnectionTesterStatus TestSignatureRequiredEnabled(Uri uri, NetworkCredential credential)
        {
            try
            {
                var tester = CreateTester(uri);
                tester.Credential = credential;
                return tester.TestSignatureRequiredEnabled(uri);
            }
            catch (LocalCallException)
            {
                return ConnectionTesterStatus.LocalCall;
            }
            catch (Exception ex)
            {
                Trace.WriteLine("Exception: " + ex.Message);
                Trace.WriteLine("StackTrace: " + ex.StackTrace);
                return ConnectionTesterStatus.InvalidData;
            }
        }

        public static ConnectionTesterStatus TestConnection(Uri uri, NetworkCredential credential)
        {
            try
            {
                var tester = CreateTester(uri);
                tester.Credential = credential;
                return tester.Test(uri, false, true);
            }
            catch (LocalCallException)
            {
                return ConnectionTesterStatus.LocalCall;
            }
            catch (Exception ex)
            {
                Trace.WriteLine("Exception: " + ex.Message);
                Trace.WriteLine("StackTrace: " + ex.StackTrace);
                return ConnectionTesterStatus.InvalidData;
            }
        }

        private class LocalCallException : Exception
        {

        }

        static bool AcceptEveryServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }


        static ConnectionTester CreateTester(Uri uri)
        {
            if (uri.Scheme == "ldaps" || uri.Scheme == "ldap")
            {
                return new ConnectionTesterLdap();
            }
            if (uri.Scheme == "https" || uri.Scheme == "http")
            {
                return new ConnectionTesterHttp();
            }
            Trace.WriteLine("Invalid scheme " + uri.Scheme);
            throw new ArgumentOutOfRangeException("uri", uri, "Scheme not supported");
        }

        protected ConnectionTesterStatus TestExtendedAuthentication(Uri uri)
        {
            Trace.WriteLine("Testing " + uri);

            Trace.WriteLine("testing WITH Extended Protection: ");
            var WithExtended = Test(uri, false, true);
            Trace.WriteLine(WithExtended.ToString());

            if (WithExtended != ConnectionTesterStatus.AuthenticationSuccessfull)
            {
                return WithExtended;
            }

            Trace.WriteLine("testing WITHOUT Extended Protection: ");
            var WithoutExtended = Test(uri, false, false);
            Trace.WriteLine(WithoutExtended.ToString());

            if (WithoutExtended != ConnectionTesterStatus.AuthenticationSuccessfull && WithoutExtended != ConnectionTesterStatus.AuthenticationFailure)
            {
                return WithExtended;
            }
            if (WithoutExtended == ConnectionTesterStatus.AuthenticationSuccessfull)
            {
                return ConnectionTesterStatus.ChannelBindingDisabled;
            }
            return ConnectionTesterStatus.ChannelBindingEnabled;
        }

        protected ConnectionTesterStatus TestSignatureRequiredEnabled(Uri uri)
        {
            Trace.WriteLine("Testing " + uri);

            Trace.WriteLine("testing WITH signature required: ");
            var WithSignature = Test(uri, false);
            Trace.WriteLine(WithSignature.ToString());

            if (WithSignature != ConnectionTesterStatus.AuthenticationSuccessfull)
            {
                return WithSignature;
            }

            Trace.WriteLine("testing WITHOUT signature required: ");
            var WithoutSignature = Test(uri, true);
            Trace.WriteLine(WithoutSignature.ToString());

            if (WithoutSignature != ConnectionTesterStatus.AuthenticationSuccessfull && WithoutSignature != ConnectionTesterStatus.AuthenticationFailure)
            {
                return WithSignature;
            }
            if (WithoutSignature == ConnectionTesterStatus.AuthenticationSuccessfull)
            {
                return ConnectionTesterStatus.SignatureNotRequired;
            }
            return ConnectionTesterStatus.SignatureRequired;
        }

        ConnectionTesterStatus Test(Uri uri, bool disableSigning = false, bool enableChannelBinding = false)
        {

            if (!Initialize())
                return ConnectionTesterStatus.InitializationFailed;

            try
            {
                int port = uri.Port;
                if (port == -1)
                {
                    port = (uri.Scheme == "ldaps" ? 636 : 389);
                }
                // default LDAPS port is 636
                using (TcpClient tcpclient = new TcpClient(uri.Host, port))
                {
                    tcpclient.SendTimeout = 1000;
                    tcpclient.ReceiveTimeout = 1000;

                    if (uri.Scheme.EndsWith("s"))
                    {
                        using (SslStream sslStream = new SslStream(tcpclient.GetStream(), false, AcceptEveryServerCertificate, null))
                        {
                            sslStream.AuthenticateAsClient(uri.Host, null, SslProtocols.Default, false);

                            if (enableChannelBinding)
                            {
                                var tc = sslStream.TransportContext;
                                var cb = tc.GetChannelBinding(ChannelBindingKind.Endpoint);
                                InitializeNTAuthentication(true, cb);
                            }
                            else
                            {
                                InitializeNTAuthentication(true);
                            }

                            return SendPackets(sslStream, uri);
                        }
                    }
                    else
                    {
                        InitializeNTAuthentication(disableSigning);
                        return SendPackets(tcpclient.GetStream(), uri);
                    }
                }
            }
            catch (Exception ex)
            {
                Trace.WriteLine("Exception: " + ex.Message);
                Trace.WriteLine("StackTrace: " + ex.StackTrace);
                return ConnectionTesterStatus.InternalError;
            }

        }

        protected abstract ConnectionTesterStatus SendPackets(Stream stream, Uri uri);

        static int GetNTLMSSPOffset(byte[] output)
        {
            for (int i = 0; i < output.Length - 24; i++)
            {
                if (output[i] == 'N' && output[i + 1] == 'T' && output[i + 2] == 'L' && output[i + 3] == 'M' &&
                    output[i + 4] == 'S' && output[i + 5] == 'S' && output[i + 6] == 'P' && output[i + 7] == '\0')
                {
                    return i;
                }
            }
            return -1;
        }

        protected string package = "Negotiate";

        object NTAuthentication;
        MethodInfo NTAuthentication_GetOutgoingBlob;
        ConstructorInfo NTAuthentication_Ctor;

        private NetworkCredential Credential;

        protected bool Initialize()
        {
            var NTAuthentication_Type = typeof(ServicePoint).Assembly.GetType("System.Net.NTAuthentication");
            if (NTAuthentication_Type == null)
            {
                Trace.WriteLine("NTAuthentication_Type failed");
                return false;
            }

            var ContextFlags_Type = typeof(ServicePoint).Assembly.GetType("System.Net.ContextFlags");
            if (ContextFlags_Type == null)
            {
                Trace.WriteLine("ContextFlags_Type failed");
                return false;
            }

            NTAuthentication_Ctor = NTAuthentication_Type.GetConstructor(
                BindingFlags.NonPublic | BindingFlags.SetField | BindingFlags.Instance, null,
                new Type[] { typeof(bool), typeof(string), typeof(NetworkCredential), typeof(string), ContextFlags_Type, typeof(ChannelBinding) },
                new ParameterModifier[6] { new ParameterModifier(), new ParameterModifier(), new ParameterModifier(), new ParameterModifier(), new ParameterModifier(), new ParameterModifier(),
                });

            if (NTAuthentication_Ctor == null)
            {
                Trace.WriteLine("NTAuthentication_Ctor failed");
                return false;
            }

            NTAuthentication_GetOutgoingBlob = NTAuthentication_Type.GetMethod("GetOutgoingBlob", BindingFlags.NonPublic | BindingFlags.Instance, null, new Type[] { typeof(string) }, new ParameterModifier[1] { new ParameterModifier() });

            if (NTAuthentication_GetOutgoingBlob == null)
            {
                Trace.WriteLine("NTAuthentication_GetOutgoingBlob failed");
                return false;
            }

            NTAuthentication = null;
            return true;
        }

        protected byte[] GetOutgoingBlob(byte[] incomingBlob)
        {
            var incomingBytes = incomingBlob == null ? null : Convert.ToBase64String(incomingBlob);

            var t = (string)NTAuthentication_GetOutgoingBlob.Invoke(NTAuthentication, new object[] { incomingBytes });

            var Response = Convert.FromBase64String(t);

            int offset = GetNTLMSSPOffset(Response);
            if (offset > 0)
            {
                var messageType = BitConverter.ToInt32(Response, offset + 8);
                if (messageType == 2)
                {
                    var flag = BitConverter.ToInt32(Response, offset + 20);
                    if ((flag & 0x00004000) != 0)
                    {
                        Trace.WriteLine("Local CALL");
                        throw new LocalCallException();
                    }
                }
            }
            return Response;
        }

        bool InitDisableSigning;
        ChannelBinding InitchannelBinding;

        protected void InitializeNTAuthentication(bool DisableSigning = false, ChannelBinding channelBinding = null)
        {
            InitDisableSigning = DisableSigning;
            InitchannelBinding = channelBinding;
            Reinit();
        }

        protected void Reinit()
        {
            // from SSPI.h
            const int ISC_REQ_NO_INTEGRITY = 0x00800000;
            const int ISC_REQ_INTEGRITY = 0x00010000;
            // these flags are transformed into System.Net.ContextFlags enum

            NTAuthentication = NTAuthentication_Ctor.Invoke(new object[] { false, package, Credential == null ? CredentialCache.DefaultCredentials : Credential, null, (InitDisableSigning ? ISC_REQ_NO_INTEGRITY : ISC_REQ_INTEGRITY), InitchannelBinding });
        }
    }
}
