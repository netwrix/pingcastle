using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Authentication.ExtendedProtection;
using System.Security.Cryptography.X509Certificates;

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

    // Performs LDAP/HTTP authentication tests to detect LDAP signing enforcement
    // and channel binding (extended protection) status on domain controllers.
    //
    // Uses direct SSPI P/Invoke (secur32.dll) rather than .NET's NegotiateAuthentication
    // because NegotiateAuthentication does not expose the ISC_REQ_NO_INTEGRITY flag
    // needed to test whether a server rejects unsigned LDAP binds.
    //
    // See SspiContext.cs for the SSPI flag details.
    abstract class ConnectionTester : IDisposable
    {
        public static ConnectionTesterStatus TestExtendedAuthentication(Uri uri, NetworkCredential credential, string logPrefix)
        {
            try
            {
                using (var tester = CreateTester(uri))
                {
                    tester.LogPrefix = logPrefix;
                    tester.Credential = credential;
                    return tester.TestExtendedAuthentication(uri);
                }
            }
            catch (LocalCallException)
            {
                return ConnectionTesterStatus.LocalCall;
            }
            catch (Exception ex)
            {
                Trace.WriteLine(logPrefix + "Exception: " + ex.Message);
                Trace.WriteLine(logPrefix + "StackTrace: " + ex.StackTrace);
                return ConnectionTesterStatus.InvalidData;
            }
        }

        public static ConnectionTesterStatus TestSignatureRequiredEnabled(Uri uri, NetworkCredential credential, string logPrefix)
        {
            try
            {
                using (var tester = CreateTester(uri))
                {
                    tester.LogPrefix = logPrefix;
                    tester.Credential = credential;
                    return tester.TestSignatureRequiredEnabled(uri);
                }
            }
            catch (LocalCallException)
            {
                return ConnectionTesterStatus.LocalCall;
            }
            catch (Exception ex)
            {
                Trace.WriteLine(logPrefix + "Exception: " + ex.Message);
                Trace.WriteLine(logPrefix + "StackTrace: " + ex.StackTrace);
                return ConnectionTesterStatus.InvalidData;
            }
        }

        public static ConnectionTesterStatus TestConnection(Uri uri, NetworkCredential credential, string logPrefix)
        {
            try
            {
                using (var tester = CreateTester(uri))
                {
                    tester.LogPrefix = logPrefix;
                    tester.Credential = credential;
                    return tester.Test(uri, false, true);
                }
            }
            catch (LocalCallException)
            {
                return ConnectionTesterStatus.LocalCall;
            }
            catch (Exception ex)
            {
                Trace.WriteLine(logPrefix + "Exception: " + ex.Message);
                Trace.WriteLine(logPrefix + "StackTrace: " + ex.StackTrace);
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

            Trace.WriteLine("CreateTester: Invalid scheme " + uri.Scheme);
            throw new ArgumentOutOfRangeException("uri", uri, "Scheme not supported");
        }

        // Tests whether channel binding (extended protection) is enforced.
        // Authenticates twice: once with channel binding, once without.
        // If both succeed, channel binding is not enforced (ESC8 / A-CertEnrollHttp).
        // If the second fails, channel binding is enforced.
        protected ConnectionTesterStatus TestExtendedAuthentication(Uri uri)
        {
            Trace.WriteLine(LogPrefix + "Testing channel binding for " + uri);

            Trace.WriteLine(LogPrefix + "Authenticating WITH channel binding token");
            var withExtended = Test(uri, false, true);
            Trace.WriteLine(LogPrefix + "WITH channel binding result: " + withExtended);

            if (withExtended != ConnectionTesterStatus.AuthenticationSuccessfull)
            {
                return withExtended;
            }

            Trace.WriteLine(LogPrefix + "Authenticating WITHOUT channel binding token");
            var withoutExtended = Test(uri, false, false);
            Trace.WriteLine(LogPrefix + "WITHOUT channel binding result: " + withoutExtended);

            if (withoutExtended != ConnectionTesterStatus.AuthenticationSuccessfull && withoutExtended != ConnectionTesterStatus.AuthenticationFailure)
            {
                return withExtended;
            }

            if (withoutExtended == ConnectionTesterStatus.AuthenticationSuccessfull)
            {
                return ConnectionTesterStatus.ChannelBindingDisabled;
            }

            return ConnectionTesterStatus.ChannelBindingEnabled;
        }

        // Tests whether LDAP signing is required by the server (A-DCLdapSign).
        // Performs two LDAP SASL binds using SSPI:
        //   1. With ISC_REQ_INTEGRITY (requests signing) - should always succeed
        //   2. With ISC_REQ_NO_INTEGRITY (explicitly no signing) - fails if server requires signing
        //
        // If both succeed, the server does not require signing (vulnerable).
        // If the second fails, the server requires signing (secure).
        //
        // Called via ldap:// (plain LDAP, port 389) from HealthcheckAnalyzer.
        protected ConnectionTesterStatus TestSignatureRequiredEnabled(Uri uri)
        {
            Trace.WriteLine(LogPrefix + "Testing LDAP signing requirement for " + uri);

            Trace.WriteLine(LogPrefix + "SASL bind WITH signing (ISC_REQ_INTEGRITY)");
            var withSignature = Test(uri, false);
            Trace.WriteLine(LogPrefix + "WITH signing result: " + withSignature);

            if (withSignature != ConnectionTesterStatus.AuthenticationSuccessfull)
            {
                Trace.WriteLine(LogPrefix + "Auth with signing failed, cannot determine signing requirement");
                return withSignature;
            }

            Trace.WriteLine(LogPrefix + "SASL bind WITHOUT signing (ISC_REQ_NO_INTEGRITY)");
            var withoutSignature = Test(uri, true);
            Trace.WriteLine(LogPrefix + "WITHOUT signing result: " + withoutSignature);

            if (withoutSignature != ConnectionTesterStatus.AuthenticationSuccessfull && withoutSignature != ConnectionTesterStatus.AuthenticationFailure)
            {
                return withSignature;
            }

            if (withoutSignature == ConnectionTesterStatus.AuthenticationSuccessfull)
            {
                Trace.WriteLine(LogPrefix + "Server accepted unsigned bind - signing NOT required");
                return ConnectionTesterStatus.SignatureNotRequired;
            }

            Trace.WriteLine(LogPrefix + "Server rejected unsigned bind - signing IS required");
            return ConnectionTesterStatus.SignatureRequired;
        }

        ConnectionTesterStatus Test(Uri uri, bool disableSigning = false, bool enableChannelBinding = false)
        {
            try
            {
                int port = uri.Port;
                if (port == -1)
                {
                    port = (uri.Scheme == "ldaps" ? 636 : 389);
                }

                using (var tcpclient = new TcpClient(uri.Host, port))
                {
                    tcpclient.SendTimeout = 1000;
                    tcpclient.ReceiveTimeout = 1000;

                    if (uri.Scheme.EndsWith("s"))
                    {
                        using (var sslStream = new SslStream(tcpclient.GetStream(), false, AcceptEveryServerCertificate, null))
                        {
                            sslStream.AuthenticateAsClient(uri.Host, null, SslProtocols.Tls | SslProtocols.Tls11 | SslProtocols.Tls12, false);

                            // For TLS connections (ldaps/https), always disable SSPI signing.
                            // TLS provides integrity at the transport layer, so SSPI signing is
                            // redundant. This path is used by channel binding tests (ESC8) and
                            // LDAPS connection tests — not by the LDAP signing test which uses
                            // plain ldap:// on port 389.
                            if (enableChannelBinding)
                            {
                                var tc = sslStream.TransportContext;
                                var cb = tc.GetChannelBinding(ChannelBindingKind.Endpoint);
                                InitializeAuthentication(true, cb);
                            }
                            else
                            {
                                InitializeAuthentication(true);
                            }

                            return SendPackets(sslStream, uri);
                        }
                    }
                    else
                    {
                        // Plain LDAP/HTTP: pass disableSigning to control SSPI flags.
                        // The signing test calls this twice: once with false (ISC_REQ_INTEGRITY)
                        // and once with true (ISC_REQ_NO_INTEGRITY).
                        InitializeAuthentication(disableSigning);
                        return SendPackets(tcpclient.GetStream(), uri);
                    }
                }
            }
            catch (Exception ex)
            {
                Trace.WriteLine(LogPrefix + "ExceptionType: " + ex.GetType());
                Trace.WriteLine(LogPrefix + "Exception: " + ex.Message);
                Trace.WriteLine(LogPrefix + "StackTrace: " + ex.StackTrace);
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
        private SspiContext _sspiContext;
        private bool _currentDisableSigning;
        private ChannelBinding _currentChannelBinding;

        public string LogPrefix { get; private set; }

        private NetworkCredential Credential;

        // Exchanges SSPI authentication tokens. Detects local loopback calls via
        // the NTLMSSP NEGOTIATE_LOCAL_CALL flag (0x4000) to avoid false results
        // when PingCastle runs directly on the DC being tested.
        protected byte[] GetOutgoingBlob(byte[] incomingBlob)
        {
            byte[] response = _sspiContext.GetToken(incomingBlob);
            if (response == null)
            {
                Trace.WriteLine(LogPrefix + "SSPI GetToken returned null (auth failed)");
                return Array.Empty<byte>();
            }

            int offset = GetNTLMSSPOffset(response);
            if (offset > 0)
            {
                var messageType = BitConverter.ToInt32(response, offset + 8);
                if (messageType == 2)
                {
                    var flag = BitConverter.ToInt32(response, offset + 20);
                    if ((flag & 0x00004000) != 0)
                    {
                        Trace.WriteLine(LogPrefix + "Local CALL detected - skipping this DC");
                        throw new LocalCallException();
                    }
                }
            }

            return response;
        }

        protected void InitializeAuthentication(bool disableSigning = false, ChannelBinding channelBinding = null)
        {
            _currentDisableSigning = disableSigning;
            _currentChannelBinding = channelBinding;

            _sspiContext?.Dispose();
            _sspiContext = new SspiContext();

            Trace.WriteLine(LogPrefix + "SSPI init: package=" + package
                + " disableSigning=" + disableSigning
                + " channelBinding=" + (channelBinding != null));

            _sspiContext.Initialize(package, disableSigning, Credential, channelBinding);
        }

        protected void ReinitializeAuthentication()
        {
            _sspiContext?.Dispose();
            _sspiContext = new SspiContext();
            _sspiContext.Initialize(package, _currentDisableSigning, Credential, _currentChannelBinding);
        }

        public void Dispose()
        {
            _sspiContext?.Dispose();
        }
    }
}
