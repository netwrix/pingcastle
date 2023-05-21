using PingCastle.Healthcheck;
using System;
using System.Diagnostics;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using System.Text;

namespace PingCastle.Scanners
{
    public class Smb1Protocol
    {

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Portability", "CA1900:ValueTypeFieldsShouldBePortable"), StructLayout(LayoutKind.Explicit)]
        struct SMB_Header
        {
            [FieldOffset(0)]
            public UInt32 Protocol;
            [FieldOffset(4)]
            public byte Command;
            [FieldOffset(5)]
            public int Status;
            [FieldOffset(9)]
            public byte Flags;
            [FieldOffset(10)]
            public UInt16 Flags2;
            [FieldOffset(12)]
            public UInt16 PIDHigh;
            [FieldOffset(14)]
            public UInt64 SecurityFeatures;
            [FieldOffset(22)]
            public UInt16 Reserved;
            [FieldOffset(24)]
            public UInt16 TID;
            [FieldOffset(26)]
            public UInt16 PIDLow;
            [FieldOffset(28)]
            public UInt16 UID;
            [FieldOffset(30)]
            public UInt16 MID;
        };




        const int SMB_COM_NEGOTIATE = 0x72;

        const int SMB_FLAGS_CASE_INSENSITIVE = 0x08;
        const int SMB_FLAGS_CANONICALIZED_PATHS = 0x10;

        const int SMB_FLAGS2_LONG_NAMES = 0x0001;
        const int SMB_FLAGS2_EAS = 0x0002;

        const int SMB_FLAGS2_SECURITY_SIGNATURE_REQUIRED = 0x0010;
        const int SMB_FLAGS2_IS_LONG_NAME = 0x0040;

        const int SMB_FLAGS2_ESS = 0x0800;

        const int SMB_FLAGS2_NT_STATUS = 0x4000;
        const int SMB_FLAGS2_UNICODE = 0x8000;

        const int SMB_DB_FORMAT_DIALECT = 0x02;

        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        static byte[] GenerateSmbHeaderFromCommand(byte command)
        {
            SMB_Header header = new SMB_Header();
            header.Protocol = 0x424D53FF;
            header.Command = command;
            header.Status = 0;
            header.Flags = SMB_FLAGS_CASE_INSENSITIVE | SMB_FLAGS_CANONICALIZED_PATHS;
            header.Flags2 = SMB_FLAGS2_LONG_NAMES | SMB_FLAGS2_EAS | SMB_FLAGS2_SECURITY_SIGNATURE_REQUIRED | SMB_FLAGS2_IS_LONG_NAME | SMB_FLAGS2_ESS | SMB_FLAGS2_NT_STATUS | SMB_FLAGS2_UNICODE;
            header.PIDHigh = 0;
            header.SecurityFeatures = 0;
            header.Reserved = 0;
            header.TID = 0xffff;
            header.PIDLow = 0xFEFF;
            header.UID = 0;
            header.MID = 0;
            return getBytes(header);
        }



        static byte[] getBytes(object structure)
        {
            int size = Marshal.SizeOf(structure);
            byte[] arr = new byte[size];

            IntPtr ptr = Marshal.AllocHGlobal(size);
            Marshal.StructureToPtr(structure, ptr, true);
            Marshal.Copy(ptr, arr, 0, size);
            Marshal.FreeHGlobal(ptr);
            return arr;
        }

        static byte[] getDialect(string dialect)
        {
            byte[] dialectBytes = Encoding.ASCII.GetBytes(dialect);
            byte[] output = new byte[dialectBytes.Length + 2];
            output[0] = 2;
            output[output.Length - 1] = 0;
            Array.Copy(dialectBytes, 0, output, 1, dialectBytes.Length);
            return output;
        }

        static byte[] GetNegotiateMessage(byte[] dialect)
        {
            byte[] output = new byte[dialect.Length + 3];
            output[0] = 0;
            output[1] = (byte)dialect.Length;
            output[2] = 0;
            Array.Copy(dialect, 0, output, 3, dialect.Length);
            return output;
        }



        static byte[] GetNegotiatePacket(byte[] header, byte[] smbPacket)
        {
            byte[] output = new byte[smbPacket.Length + header.Length + 4];
            output[0] = 0;
            output[1] = 0;
            output[2] = 0;
            output[3] = (byte)(smbPacket.Length + header.Length);
            Array.Copy(header, 0, output, 4, header.Length);
            Array.Copy(smbPacket, 0, output, 4 + header.Length, smbPacket.Length);
            return output;
        }

        [SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        public static bool DoesServerSupportDialect(string server, string dialect, out SMBSecurityModeEnum securityMode, string logPrefix = null)
        {
            Trace.WriteLine(logPrefix + "Checking " + server + " for SMBV1 dialect " + dialect);
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
                byte[] header = GenerateSmbHeaderFromCommand(SMB_COM_NEGOTIATE);
                byte[] dialectEncoding = getDialect(dialect);
                byte[] negotiatemessage = GetNegotiateMessage(dialectEncoding);
                byte[] packet = GetNegotiatePacket(header, negotiatemessage);
                stream.Write(packet, 0, packet.Length);
                stream.Flush();
                byte[] netbios = new byte[4];
                if (stream.Read(netbios, 0, netbios.Length) != netbios.Length)
                    return false;
                byte[] smbHeader = new byte[Marshal.SizeOf(typeof(SMB_Header))];
                if (stream.Read(smbHeader, 0, smbHeader.Length) != smbHeader.Length)
                    return false;
                byte[] negotiateresponse = new byte[4];
                if (stream.Read(negotiateresponse, 0, negotiateresponse.Length) != negotiateresponse.Length)
                    return false;
                if (negotiateresponse[1] == 0 && negotiateresponse[2] == 0)
                {
                    Trace.WriteLine(logPrefix + "Checking " + server + " for SMBV1 dialect " + dialect + " = Supported");
                    byte SmbSecurityMode = negotiateresponse[3];
                    if (SmbSecurityMode == 4)
                    {
                        securityMode = SMBSecurityModeEnum.SmbSigningEnabled;
                    }
                    else if (SmbSecurityMode == 8)
                    {
                        securityMode = SMBSecurityModeEnum.SmbSigningEnabled | SMBSecurityModeEnum.SmbSigningRequired;
                    }
                    else
                    {
                        securityMode = SMBSecurityModeEnum.None;
                    }
                    return true;
                }
                Trace.WriteLine(logPrefix + "Checking " + server + " for SMBV1 dialect " + dialect + " = Not supported");
                return false;
            }
            catch (Exception)
            {
                throw new Smb1NotSupportedException(server);
            }
        }
    }
}
