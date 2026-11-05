#nullable enable
namespace PingCastle.Scanners;

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Healthcheck;
using PingCastleCommon.RPC;
using PingCastleCommon.Scanners;

public class Smb2ProtocolTest
{
    private readonly ISSPIHelperFactory _sspiHelperFactory;

    public Smb2ProtocolTest(ISSPIHelperFactory sspiHelperFactory)
    {
        ArgumentNullException.ThrowIfNull(sspiHelperFactory);
        _sspiHelperFactory = sspiHelperFactory;
    }

    public bool DoesServerSupportDialectWithSmbV2(string server, int dialect, out SMBSecurityModeEnum securityMode, string logPrefix = null)
    {
        Trace.WriteLine(logPrefix + "Checking " + server + " for SMBV2 dialect 0x" + dialect.ToString("X2"));
        securityMode = SMBSecurityModeEnum.NotTested;
        TcpClient client = new TcpClient();
        client.ReceiveTimeout = 500;
        client.SendTimeout = 500;

        try
        {
            client.Connect(server, 445);
        }
        catch (Exception)
        {
            throw new SmbPortClosedException(server);
        }

        try
        {
            NetworkStream stream = client.GetStream();

            var smb2 = new Smb2Protocol(stream, server, _sspiHelperFactory);
            smb2.LogPrefix = logPrefix;
            var negotiateresponse = smb2.SendNegotiateRequest(dialect);

            if ((negotiateresponse.SecurityMode & 1) != 0)
            {
                securityMode = SMBSecurityModeEnum.SmbSigningEnabled;
                if ((negotiateresponse.SecurityMode & 2) != 0)
                {
                    securityMode |= SMBSecurityModeEnum.SmbSigningRequired;
                }
            }
            else
            {
                securityMode = SMBSecurityModeEnum.None;
            }

            Trace.WriteLine(logPrefix + "Checking " + server + " for SMBV2 dialect 0x" + dialect.ToString("X2") + " = Supported");
            return true;
        }
        catch (Win32Exception ex)
        {
            // NOTE: Catching Win32Exception separately to provide more specific logging, but this will not be thrown on a
            //  non-windows platform.

            // Handle specific Win32 exceptions differently 
            Trace.WriteLine(logPrefix + "Checking " + server + " for SMBV2 dialect 0x" + dialect.ToString("X2") +
                            " = Win32 error: 0x" + ex.NativeErrorCode.ToString("X8") + " - " + ex.Message);
            return false;
        }
        catch (Exception ex)
        {
            // This gives us details on what's failing in our implementation
            Trace.WriteLine(logPrefix + "Checking " + server + " for SMBV2 dialect 0x" + dialect.ToString("X2") +
                            " = Exception error: " + ex.GetType().Name + " - " + ex.Message);

            // For debugging purposes, log the stack trace too
            Trace.WriteLine(logPrefix + "Stack trace: " + ex.StackTrace);

            if (dialect == (int)Smb2Protocol.SMB2_DIALECTS.SMB2_DIALECT_3_1_1)
            {
                // Special handling for SMB 3.1.1
                Trace.WriteLine(logPrefix + "SMB 3.1.1 specific error: " + ex.Message);
                return false;
            }

            // For other dialects, maintain the original behavior
            return false;
        }
        finally
        {
            client.Close();
        }
    }

    public List<NetworkInfo> GetFCTL_QUERY_NETWORK_INFO(string server, NetworkCredential credential = null)
    {
        Trace.WriteLine("Checking " + server + " for GetFCTL_QUERY_NETWORK_INFO");
        TcpClient client = new TcpClient();
        client.ReceiveTimeout = 500;
        client.SendTimeout = 500;
        try
        {
            client.Connect(server, 445);
        }
        catch (Exception)
        {
            Trace.WriteLine("Error with " + server + "(port closed)");
            return null;
        }

        try
        {
            NetworkStream stream = client.GetStream();
            var smb2 = new Smb2Protocol(stream, server, _sspiHelperFactory);

            smb2.SendNegotiateRequest(0x0302);

            smb2.SendSessionSetupRequests(credential);

            smb2.SendTreeConnect("\\\\" + server + "\\IPC$");

            var o = smb2.GetNetworkInterfaceInfo();

            client.Close();

            return o;
        }
        catch (Exception ex)
        {
            Trace.WriteLine("Error with " + server + "(" + ex.Message + ")");
            return null;
        }
    }
}