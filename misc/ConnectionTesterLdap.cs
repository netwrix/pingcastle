using System;
using System.Diagnostics;
using System.DirectoryServices.Protocols;
using System.IO;

namespace PingCastle.misc
{
    class ConnectionTesterLdap : ConnectionTester
    {

        // we are using the native Windows Ber encoder to build the LDAP message bindRequest
        // problem: it does not recognize CHOICE or other BER encoding structure.
        // given the fact that these structures are located at the beginning of the message
        // we replace the SEQUENCE (0x30) by the expected BER Tags
        void SendBindRequestMessage(Stream stream, int messageNum, byte[] challengeResponseData)
        {
            var o = BerConverter.Encode("{i{is{so}}}", messageNum, 3, null, "GSS-SPNEGO", challengeResponseData);
            o[9] = 0x60; // replace sequence
            o[20] = 0xA3; // replace sequence
            stream.Write(o, 0, o.Length);
        }

        // same problem for parsing incoming message
        // if there is an error message, the second replacement is in a variable place
        // that's why there are 2 paths.
        // if there is no error, the SASL is at a fixed place and we can use the same trick
        // (the BER parser expect a SEQUENCE - aka 0x30 or BYTE array - aka 04)
        object[] ReceiveBindResponseMessage(Stream stream)
        {
            // we expect the message to be less than 1kB
            byte[] buffer = new byte[1024];
            var r = stream.Read(buffer, 0, 1024);
            byte[] output = new byte[r];
            Array.Copy(buffer, output, r);

            output[0x9] = 0x30;

            // no error message
            if (output[0x16] == 0x87)
            {
                output[0x16] = 0x04;
                return BerConverter.Decode("{i{iaaO}}", output);
            }
            // error message
            return BerConverter.Decode("{i{iaa}}", output);
        }

        protected override ConnectionTesterStatus SendPackets(Stream stream, Uri uri)
        {
            byte[] Response = null;
            for (int i = 0; i < 10; i++)
            {
                var Challenge = GetOutgoingBlob(Response);

                SendBindRequestMessage(stream, i + 1, Challenge);

                var r1 = ReceiveBindResponseMessage(stream);
                if (r1.Length < 1)
                {
                    Trace.WriteLine("No data returned");
                    return ConnectionTesterStatus.InternalError;
                }
                var code = (int)r1[1];

                if (code == 0)
                {
                    if (i == 0)
                        return ConnectionTesterStatus.NoAuthenticationNeeded;
                    return ConnectionTesterStatus.AuthenticationSuccessfull;
                }
                if (code == 14 && r1.Length > 4)
                {
                    Response = (byte[])r1[4];
                    // should not happen
                    if (Response == null)
                        return ConnectionTesterStatus.AuthenticationFailure;

                    continue;
                }
                Trace.WriteLine("Unexpected error code: " + code);
                Trace.WriteLine("Error message: " + r1[3]);
                return ConnectionTesterStatus.AuthenticationFailure;
            }
            Trace.WriteLine("Authentication attempts stopped");
            return ConnectionTesterStatus.AuthenticationFailure;
        }

        
    }
}
