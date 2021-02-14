using PingCastle.Healthcheck;
using PingCastle.RPC;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Permissions;
using System.Text;

namespace PingCastle.Scanners
{
    public class Smb2Protocol
    {
        public enum SBM2_Command
        {
            SMB2_NEGOTIATE = 0,
            SMB2_SESSION_SETUP = 1,
            SMB2_TREE_CONNECT = 3,
            SMB2_IOCTL = 0x000B,
        }

        private static byte[] mechTypes = new byte[] { 0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a, };

        public const uint STATUS_MORE_PROCESSING_REQUIRED = 0xc0000016;

        // https://msdn.microsoft.com/en-us/library/cc246529.aspx
        [StructLayout(LayoutKind.Explicit)]
        public struct SMB2_Header
        {
            [FieldOffset(0)]
            public UInt32 ProtocolId;
            [FieldOffset(4)]
            public UInt16 StructureSize;
            [FieldOffset(6)]
            public UInt16 CreditCharge;
            [FieldOffset(8)]
            public UInt32 Status; // to do SMB3
            [FieldOffset(12)]
            public UInt16 Command;
            [FieldOffset(14)]
            public UInt16 CreditRequest_Response;
            [FieldOffset(16)]
            public UInt32 Flags;
            [FieldOffset(20)]
            public UInt32 NextCommand;
            [FieldOffset(24)]
            public UInt64 MessageId;
            [FieldOffset(32)]
            public UInt32 Reserved;
            [FieldOffset(36)]
            public UInt32 TreeId;
            [FieldOffset(40)]
            public UInt64 SessionId;
            [FieldOffset(48)]
            public UInt64 Signature1;
            [FieldOffset(56)]
            public UInt64 Signature2;
        }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Portability", "CA1900:ValueTypeFieldsShouldBePortable"), StructLayout(LayoutKind.Explicit)]
        public struct SMB2_NegotiateRequest
        {
            [FieldOffset(0)]
            public UInt16 StructureSize;
            [FieldOffset(2)]
            public UInt16 DialectCount;
            [FieldOffset(4)]
            public UInt16 SecurityMode;
            [FieldOffset(6)]
            public UInt16 Reserved;
            [FieldOffset(8)]
            public UInt32 Capabilities;
            [FieldOffset(12)]
            public Guid ClientGuid;
            [FieldOffset(28)]
            public UInt64 ClientStartTime;
            [FieldOffset(36)]
            public UInt16 DialectToTest;
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Portability", "CA1900:ValueTypeFieldsShouldBePortable"), StructLayout(LayoutKind.Explicit)]
        public struct SMB2_NegotiateResponse
        {
            [FieldOffset(0)]
            public UInt16 StructureSize;
            [FieldOffset(2)]
            public byte SecurityMode;
            [FieldOffset(3)]
            public UInt16 Dialect;
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Portability", "CA1900:ValueTypeFieldsShouldBePortable"), StructLayout(LayoutKind.Explicit)]
        public struct SMB2_SessionSetupResponse
        {
            [FieldOffset(0)]
            public UInt16 StructureSize;
            [FieldOffset(2)]
            public UInt16 SessionFlags;
            [FieldOffset(4)]
            public UInt16 SecurityBufferOffset;
            [FieldOffset(6)]
            public UInt16 SecurityBufferLength;

        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Portability", "CA1900:ValueTypeFieldsShouldBePortable"), StructLayout(LayoutKind.Explicit)]
        public struct SMB2_SessionSetup
        {
            [FieldOffset(0)]
            public UInt16 StructureSize;
            [FieldOffset(2)]
            public byte Flags;
            [FieldOffset(3)]
            public byte SecurityMode;
            [FieldOffset(4)]
            public UInt32 Capabilities;
            [FieldOffset(8)]
            public UInt32 Channel;
            [FieldOffset(12)]
            public UInt16 SecurityBufferOffset;
            [FieldOffset(14)]
            public UInt16 SecurityBufferLength;
            [FieldOffset(16)]
            public UInt64 PreviousSessionId;
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Portability", "CA1900:ValueTypeFieldsShouldBePortable"), StructLayout(LayoutKind.Explicit)]
        public struct SMB2_TreeConnect
        {
            [FieldOffset(0)]
            public UInt16 StructureSize;
            [FieldOffset(2)]
            public UInt16 Flags;
            [FieldOffset(4)]
            public UInt16 PathOffset;
            [FieldOffset(6)]
            public UInt16 PathLength;
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Portability", "CA1900:ValueTypeFieldsShouldBePortable"), StructLayout(LayoutKind.Explicit)]
        public struct SMB2_TreeConnectResponse
        {
            [FieldOffset(0)]
            public UInt16 StructureSize;
            [FieldOffset(2)]
            public byte ShareType;
            [FieldOffset(4)]
            public UInt32 ShareFlags;
            [FieldOffset(8)]
            public UInt32 Capabilities;
            [FieldOffset(12)]
            public UInt32 MaximalAccess;
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Portability", "CA1900:ValueTypeFieldsShouldBePortable"), StructLayout(LayoutKind.Explicit)]
        public struct SMB2_IOCTLRequest
        {
            [FieldOffset(0)]
            public UInt16 StructureSize;
            [FieldOffset(4)]
            public UInt32 CtlCode;
            [FieldOffset(8)]
            public Guid FileId;
            [FieldOffset(24)]
            public UInt32 InputOffset;
            [FieldOffset(28)]
            public UInt32 InputCount;
            [FieldOffset(32)]
            public UInt32 MaxInputResponse;
            [FieldOffset(36)]
            public UInt32 OutputOffset;
            [FieldOffset(40)]
            public UInt32 OutputCount;
            [FieldOffset(44)]
            public UInt32 MaxOutputResponse;
            [FieldOffset(48)]
            public UInt32 Flags;
            [FieldOffset(52)]
            public UInt32 Reserved2;
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Portability", "CA1900:ValueTypeFieldsShouldBePortable"), StructLayout(LayoutKind.Explicit)]
        public struct SMB2_IOCTLResponse
        {
            [FieldOffset(0)]
            public UInt16 StructureSize;
            [FieldOffset(4)]
            public UInt32 CtlCode;
            [FieldOffset(8)]
            public Guid FileId;
            [FieldOffset(24)]
            public UInt32 InputOffset;
            [FieldOffset(28)]
            public UInt32 InputCount;
            [FieldOffset(32)]
            public UInt32 OutputOffset;
            [FieldOffset(36)]
            public UInt32 OutputCount;
            [FieldOffset(40)]
            public UInt32 Flags;
            [FieldOffset(44)]
            public UInt32 Reserved2;
        }

        [Flags]
        public enum SMB2_NETWORK_INTERFACE_INFO_Capability : uint
        {
            None = 0,
            RSS_CAPABLE = 1,
            RDMA_CAPABLE = 2,
        }

        public struct SMB2_NETWORK_INTERFACE_INFO
        {
            public int Next;
            public UInt32 IfIndex;
            public SMB2_NETWORK_INTERFACE_INFO_Capability Capability;
            public UInt32 Reserved;
            public UInt64 LinkSpeed;
            public UInt16 SockAddr_Storage_Family;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 14)]
            public byte[] SockAddr_Storage_Buffer;
        }

        public class NetworkInfo
        {
            public SMB2_NETWORK_INTERFACE_INFO_Capability Capability { get; set; }
            public ulong LinkSpeed { get; set; }
            public IPAddress IP { get; set; }

            public uint Index { get; set; }
        }

        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        public byte[] GenerateSmb2HeaderFromCommand(SBM2_Command command)
        {
            SMB2_Header header = new SMB2_Header();
            header.ProtocolId = 0x424D53FE;
            header.Command = (byte)command;
            header.StructureSize = 64;
            header.MessageId = _messageId++;
            header.Reserved = 0xFEFF;
            header.SessionId = _sessionid;
            header.TreeId = _TreeId;
            return getBytes(header);
        }



        public static byte[] getBytes(object structure)
        {
            int size = Marshal.SizeOf(structure);
            byte[] arr = new byte[size];

            IntPtr ptr = Marshal.AllocHGlobal(size);
            Marshal.StructureToPtr(structure, ptr, true);
            Marshal.Copy(ptr, arr, 0, size);
            Marshal.FreeHGlobal(ptr);
            return arr;
        }

        // MS-SMB2  2.2.3 SMB2 NEGOTIATE Request
        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        public static byte[] GetNegotiateMessageSmbv2(int DialectToTest)
        {
            SMB2_NegotiateRequest request = new SMB2_NegotiateRequest();
            request.StructureSize = 36;
            request.DialectCount = 1;
            request.SecurityMode = 1; // signing enabled
            request.ClientGuid = Guid.NewGuid();
            request.DialectToTest = (UInt16)DialectToTest;
            request.Capabilities = 1; //DFS
            return getBytes(request);
        }

        // MS-SMB2  2.2.3 SMB2 NEGOTIATE Request
        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        public static byte[] GetSessionSetupMessageSmbv2(int securityBufferLength)
        {
            var request = new SMB2_SessionSetup();
            request.StructureSize = 25;
            request.Flags = 0;
            request.SecurityMode = 1; // signing enabled
            request.Capabilities = 1; //DFS
            request.Channel = 0;
            request.PreviousSessionId = 0;
            request.SecurityBufferLength = (ushort)securityBufferLength;
            request.SecurityBufferOffset = (ushort)(Marshal.SizeOf(typeof(SMB2_SessionSetup)) + Marshal.SizeOf(typeof(SMB2_Header)));
            return getBytes(request);
        }

        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        public static byte[] GetTreeConnectMessageSmbv2(int targetlen)
        {
            var request = new SMB2_TreeConnect();
            request.StructureSize = 9;
            request.Flags = 0;
            request.PathOffset = (ushort)(Marshal.SizeOf(typeof(SMB2_Header)) + Marshal.SizeOf(typeof(SMB2_TreeConnect)));
            request.PathLength = (ushort)(targetlen * 2);
            return getBytes(request);
        }

        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        public static byte[] GetIOCTLRequest(uint CTLCode, bool IsFSCTL)
        {
            var request = new SMB2_IOCTLRequest();
            request.StructureSize = 57;
            request.CtlCode = CTLCode;
            request.FileId = new Guid("ffffffff-ffff-ffff-ffff-ffffffffffff");
            request.InputOffset = (uint)(Marshal.SizeOf(typeof(SMB2_Header)) + Marshal.SizeOf(typeof(SMB2_IOCTLRequest)));
            request.OutputOffset = request.InputOffset;
            request.MaxOutputResponse = 0x10000;
            request.MaxInputResponse = 0;
            request.Flags = (uint)(IsFSCTL ? 1 : 0);
            return getBytes(request);
        }

        public static byte[] GetGSSSpNegoToken(int NTLMTokenLen)
        {
            // brutal ASN1 encoding - use https://lapo.it/asn1js to verify it
            return new byte[]
            {
                0x60, (byte) (NTLMTokenLen + 32),
                    0x06, 0x06,
                        0x2b, 0x06, 0x01, 0x05, 0x05, 0x02,
                    0xa0, (byte) (NTLMTokenLen + 22),
                        0x30, (byte) (NTLMTokenLen + 20),
                            0xa0, 0x0e,
                                0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a,
                            0xa2, (byte) (NTLMTokenLen + 2),
                                0x04, (byte) NTLMTokenLen
            };
        }

        public static byte[] GetGSSSpNegoToken2(int NTLMTokenLen, int MIClen)
        {
            // brutal ASN1 encoding - use https://lapo.it/asn1js to verify it
            return new byte[]
            {
                0xa1,0x82,HighByte(NTLMTokenLen+17+MIClen),LowByte(NTLMTokenLen+17+MIClen),
                    0x30,0x82,HighByte(NTLMTokenLen+13+MIClen),LowByte(NTLMTokenLen+13+MIClen),
                        0xa0,0x03,0x0a,0x01,0x01,
                        0xa2,0x82,HighByte(NTLMTokenLen+4),LowByte(NTLMTokenLen+4),
                            0x04,0x82,HighByte(NTLMTokenLen),LowByte(NTLMTokenLen)
            };
        }

        static byte LowByte(int size)
        {
            return (byte)(size % 0x100);
        }

        static byte HighByte(int size)
        {
            return (byte)(size / 0x100);
        }

        static byte[] AESEncrypt(byte[] key, byte[] iv, byte[] data)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                var aes = Rijndael.Create();

                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.None;

                using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(key, iv), CryptoStreamMode.Write))
                {
                    cs.Write(data, 0, data.Length);
                    cs.FlushFinalBlock();

                    return ms.ToArray();
                }
            }
        }

        static byte[] Rol(byte[] b)
        {
            byte[] r = new byte[b.Length];
            byte carry = 0;

            for (int i = b.Length - 1; i >= 0; i--)
            {
                ushort u = (ushort)(b[i] << 1);
                r[i] = (byte)((u & 0xff) + carry);
                carry = (byte)((u & 0xff00) >> 8);
            }

            return r;
        }

        byte[] AESCMAC(byte[] key, byte[] data)
        {
            // SubKey generation
            // step 1, AES-128 with key K is applied to an all-zero input block.
            byte[] L = AESEncrypt(key, new byte[16], new byte[16]);

            // step 2, K1 is derived through the following operation:
            byte[] FirstSubkey = Rol(L); //If the most significant bit of L is equal to 0, K1 is the left-shift of L by 1 bit.
            if ((L[0] & 0x80) == 0x80)
                FirstSubkey[15] ^= 0x87; // Otherwise, K1 is the exclusive-OR of const_Rb and the left-shift of L by 1 bit.

            // step 3, K2 is derived through the following operation:
            byte[] SecondSubkey = Rol(FirstSubkey); // If the most significant bit of K1 is equal to 0, K2 is the left-shift of K1 by 1 bit.
            if ((FirstSubkey[0] & 0x80) == 0x80)
                SecondSubkey[15] ^= 0x87; // Otherwise, K2 is the exclusive-OR of const_Rb and the left-shift of K1 by 1 bit.

            byte[] d = new byte[((int)data.Length / 16) * 16];
            Array.Copy(data, d, data.Length);

            // MAC computing
            if (((data.Length != 0) && (data.Length % 16 == 0)) == true)
            {
                // If the size of the input message block is equal to a positive multiple of the block size (namely, 128 bits),
                // the last block shall be exclusive-OR'ed with K1 before processing
                for (int j = 0; j < FirstSubkey.Length; j++)
                    d[d.Length - 16 + j] ^= FirstSubkey[j];
            }
            else
            {
                // Otherwise, the last block shall be padded with 10^i

                d[data.Length] = 0x80;

                for (int i = 1; i < 16 - data.Length % 16; i++)
                {
                    d[data.Length + i] = 0;
                }

                // and exclusive-OR'ed with K2
                for (int j = 0; j < SecondSubkey.Length; j++)
                    d[d.Length - 16 + j] ^= SecondSubkey[j];
            }

            // The result of the previous process will be the input of the last encryption.
            byte[] encResult = AESEncrypt(key, new byte[16], d);

            byte[] HashValue = new byte[16];
            Array.Copy(encResult, encResult.Length - HashValue.Length, HashValue, 0, HashValue.Length);

            return HashValue;
        }

        public byte[] BuildNegotiatePacket(int dialect)
        {
            byte[] header = GenerateSmb2HeaderFromCommand(SBM2_Command.SMB2_NEGOTIATE);
            byte[] negotiatemessage = GetNegotiateMessageSmbv2(dialect);
            return BuildPacket(header, negotiatemessage);
        }

        public byte[] BuildSessionSetupPacket(byte[] NTLMSSPMessage, byte[] MIC)
        {
            int MIClen = (MIC == null ? 0 : MIC.Length + 4);
            byte[] header = GenerateSmb2HeaderFromCommand(SBM2_Command.SMB2_SESSION_SETUP);
            byte[] SpNegoToken = _sessionid == 0 ? GetGSSSpNegoToken(NTLMSSPMessage.Length)
                : GetGSSSpNegoToken2(NTLMSSPMessage.Length, MIClen);
            byte[] message = GetSessionSetupMessageSmbv2(SpNegoToken.Length + NTLMSSPMessage.Length + MIClen);
            byte[] MICPrefix = null;
            if (MIC != null)
            {
                MICPrefix = new byte[] { 0xA3, LowByte(MIC.Length + 2), 0x04, LowByte(MIC.Length) };
            }
            return BuildPacket(header, message, SpNegoToken, NTLMSSPMessage, MICPrefix, MIC);
        }

        public byte[] BuildTreeConnectPacket(string target)
        {
            byte[] header = GenerateSmb2HeaderFromCommand(SBM2_Command.SMB2_TREE_CONNECT);
            byte[] data = Encoding.Unicode.GetBytes(target);
            byte[] message = GetTreeConnectMessageSmbv2(target.Length);
            return BuildPacket(header, message, data);
        }

        public byte[] BuildIOCTLRequestPacket(uint CTLCode, bool IsFSCTL)
        {
            byte[] header = GenerateSmb2HeaderFromCommand(SBM2_Command.SMB2_IOCTL);
            byte[] message = GetIOCTLRequest(CTLCode, IsFSCTL);
            return BuildPacket(header, message);
        }

        public byte[] ReadPacket()
        {
            byte[] netbios = new byte[4];
            if (_stream.Read(netbios, 0, netbios.Length) != netbios.Length)
                throw new Smb2NotWellFormatedException(_server);
            int size = netbios[0] << 24 | netbios[1] << 16 | netbios[2] << 8 | netbios[3] << 0;
            byte[] output = new byte[size];
            _stream.Read(output, 0, size);
            return output;
        }

        SMB2_Header ReadSMB2Header(byte[] packet)
        {
            GCHandle handle = GCHandle.Alloc(packet, GCHandleType.Pinned);
            SMB2_Header header = (SMB2_Header)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(SMB2_Header));
            handle.Free();
            return header;
        }

        public static T ReadResponse<T>(byte[] packet) where T : struct
        {
            GCHandle handle = GCHandle.Alloc(packet, GCHandleType.Pinned);
            T header = (T)Marshal.PtrToStructure(new IntPtr(handle.AddrOfPinnedObject().ToInt64() + Marshal.SizeOf(typeof(SMB2_Header))), typeof(T));
            handle.Free();
            return header;
        }

        public static byte[] BuildPacket(params byte[][] bytes)
        {
            int size = 0;
            foreach (var array in bytes)
            {
                if (array == null)
                    continue;
                size += array.Length;
            }
            byte[] output = new byte[size + 4];
            var byteSize = BitConverter.GetBytes(size);
            output[0] = byteSize[3];
            output[1] = byteSize[2];
            output[2] = byteSize[1];
            output[3] = byteSize[0];
            int offset = 4;
            foreach (var array in bytes)
            {
                if (array == null)
                    continue;
                Array.Copy(array, 0, output, offset, array.Length);
                offset += array.Length;
            }
            return output;
        }

        public static byte[] ExtractSSP(byte[] answer, SMB2_SessionSetupResponse sessionSetupResponse)
        {
            int offset;
            for (offset = sessionSetupResponse.SecurityBufferOffset;
                offset + 4 < sessionSetupResponse.SecurityBufferLength - sessionSetupResponse.SecurityBufferOffset;
                offset++)
            {
                if (answer[offset] == 0x4e
                    && answer[offset + 1] == 0x54
                    && answer[offset + 2] == 0x4c
                    && answer[offset + 3] == 0x4d
                    && answer[offset + 4] == 0x53
                    && answer[offset + 5] == 0x53
                    && answer[offset + 6] == 0x50
                    && answer[offset + 7] == 0x00)
                {
                    offset = offset - sessionSetupResponse.SecurityBufferOffset;
                    var NegoPacket2 = new byte[sessionSetupResponse.SecurityBufferLength - offset];
                    Array.Copy(answer, sessionSetupResponse.SecurityBufferOffset + offset, NegoPacket2, 0, sessionSetupResponse.SecurityBufferLength - offset);
                    return NegoPacket2;
                }
            }
            throw new ApplicationException("SSP answer not found");
        }

        void SendPacket(byte[] packet)
        {

            _stream.Write(packet, 0, packet.Length);
            _stream.Flush();
        }

        private Stream _stream;
        private string _server;

        ulong _sessionid = 0;
        ulong _messageId = 0;
        byte[] sessionkey;
        uint _TreeId;

        public Smb2Protocol(Stream stream, string server)
        {
            _stream = stream;
            _server = server;
        }

        public SMB2_NegotiateResponse SendNegotiateRequest(int dialect)
        {
            byte[] packet = BuildNegotiatePacket(dialect);
            _stream.Write(packet, 0, packet.Length);
            _stream.Flush();
            Trace.WriteLine("Negotiate Packet sent");

            byte[] answer = ReadPacket();
            Trace.WriteLine("Negotiate Packet received");
            var header = ReadSMB2Header(answer);

            if (header.Status != 0)
            {
                Trace.WriteLine("Checking " + _server + " for SMBV2 dialect 0x" + dialect.ToString("X2") + " = Not supported via error code");
                throw new Win32Exception((int)header.Status);
            }

            return ReadResponse<SMB2_NegotiateResponse>(answer);
        }

        public SMB2_SessionSetupResponse SendSessionSetupRequests(NetworkCredential optionalCredential = null)
        {
            SSPIHelper MyHelper = new SSPIHelper(_server);
            if (optionalCredential != null)
            {
                MyHelper.LoginClient(optionalCredential);
            }
            byte[] ServerSSPIPacket = null;
            byte[] ClientSSPIPacket;
            byte[] MIC = null;
            bool bContinueProcessing = true;
            while (bContinueProcessing)
            {
                MyHelper.InitializeClient(out ClientSSPIPacket, ServerSSPIPacket, out bContinueProcessing);
                if (!bContinueProcessing)
                {
                    byte[] temp;
                    MyHelper.SignMessage(mechTypes, out temp);
                    MIC = new byte[temp.Length - mechTypes.Length];
                    Array.Copy(temp, mechTypes.Length, MIC, 0, temp.Length - mechTypes.Length);
                    sessionkey = MyHelper.GetSessionKey();
                }
                var packet = BuildSessionSetupPacket(ClientSSPIPacket, MIC);
                SendPacket(packet);

                Trace.WriteLine("SessionSetup Packet sent");
                var answer = ReadPacket();
                var header = ReadSMB2Header(answer);
                Trace.WriteLine("SessionSetup Packet received");
                if (header.Status == 0)
                {
                    return ReadResponse<SMB2_SessionSetupResponse>(answer);
                }
                if (header.Status != STATUS_MORE_PROCESSING_REQUIRED)
                {
                    Trace.WriteLine("Checking " + _server + "Error " + header.Status);
                    throw new Win32Exception((int)header.Status);
                }
                if (!bContinueProcessing)
                {
                    Trace.WriteLine("Checking " + _server + "Error " + header.Status + " when no processing needed");
                    throw new Win32Exception((int)header.Status, "Unexpected SessionSetup error");
                }

                var sessionSetupResponse = ReadResponse<SMB2_SessionSetupResponse>(answer);

                _sessionid = header.SessionId;
                // extract SSP answer from GSSPAPI answer
                ServerSSPIPacket = ExtractSSP(answer, sessionSetupResponse);
            }
            throw new NotImplementedException("Not supposed to be here");
        }

        public SMB2_TreeConnectResponse SendTreeConnect(string target)
        {
            var packet = BuildTreeConnectPacket(target);
            SendPacket(packet);

            Trace.WriteLine("TreeConnect Packet sent");
            var answer = ReadPacket();
            var header = ReadSMB2Header(answer);
            Trace.WriteLine("TreeConnect Packet received");
            if (header.Status != 0)
            {
                Trace.WriteLine("Checking " + _server + "Error " + header.Status);
                throw new Win32Exception((int)header.Status);
            }
            var r = ReadResponse<SMB2_TreeConnectResponse>(answer);
            _TreeId = header.TreeId;
            return r;
        }

        public byte[] SendIOCTLRequest(uint CTLCode, bool IsFSCTL)
        {
            var packet = BuildIOCTLRequestPacket(CTLCode, IsFSCTL);
            SendPacket(packet);

            Trace.WriteLine("IOCTLRequest Packet sent");
            var answer = ReadPacket();
            var header = ReadSMB2Header(answer);
            Trace.WriteLine("IOCTLRequest Packet received");
            if (header.Status != 0)
            {
                Trace.WriteLine("Checking " + _server + "Error " + header.Status);
                throw new Win32Exception((int)header.Status);
            }
            var response = ReadResponse<SMB2_IOCTLResponse>(answer);
            if (response.OutputCount == 0)
                return null;
            var output = new byte[response.OutputCount];
            Array.Copy(answer, response.OutputOffset, output, 0, response.OutputCount);
            return output;
        }

        public List<NetworkInfo> GetNetworkInterfaceInfo()
        {
            var output = new List<NetworkInfo>();
            var o = SendIOCTLRequest(0x001401FC, true);

            int size = Marshal.SizeOf(typeof(SMB2_NETWORK_INTERFACE_INFO));
            int offset = 0;
            do
            {
                IntPtr pt = Marshal.AllocHGlobal(size);
                Marshal.Copy(o, offset, pt, size);
                var n = (SMB2_NETWORK_INTERFACE_INFO)Marshal.PtrToStructure(pt, typeof(SMB2_NETWORK_INTERFACE_INFO));

                var ni = new NetworkInfo();
                ni.Index = n.IfIndex;
                ni.Capability = n.Capability;
                ni.LinkSpeed = n.LinkSpeed;
                if (n.SockAddr_Storage_Family == 0x2)
                {
                    var t = new byte[4];
                    Array.Copy(o, offset + Marshal.OffsetOf(typeof(SMB2_NETWORK_INTERFACE_INFO), "SockAddr_Storage_Buffer").ToInt32() + 2, t, 0, t.Length);
                    ni.IP = new IPAddress(t);
                }
                else if (n.SockAddr_Storage_Family == 0x17)
                {
                    var t = new byte[16];
                    Array.Copy(o, offset + Marshal.OffsetOf(typeof(SMB2_NETWORK_INTERFACE_INFO), "SockAddr_Storage_Buffer").ToInt32() + 6, t, 0, t.Length);
                    ni.IP = new IPAddress(t);
                }
                else throw new NotImplementedException("SockAddr_Storage_Family unknown: " + n.SockAddr_Storage_Family);


                output.Add(ni);
                Marshal.FreeHGlobal(pt);

                if (n.Next == 0)
                    break;

                offset += n.Next;
            } while (offset != 0);
            return output;
        }


    }
    public class Smb2ProtocolTest
    {
        [SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        public static bool DoesServerSupportDialectWithSmbV2(string server, int dialect, out SMBSecurityModeEnum securityMode)
        {
            Trace.WriteLine("Checking " + server + " for SMBV2 dialect 0x" + dialect.ToString("X2"));
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

                var smb2 = new Smb2Protocol(stream, server);

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

                Trace.WriteLine("Checking " + server + " for SMBV2 dialect 0x" + dialect.ToString("X2") + " = Supported");
                return true;
            }
            catch (Exception)
            {
                throw new Smb2NotSupportedException(server);
            }
        }


        [SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        public static List<Smb2Protocol.NetworkInfo> GetFCTL_QUERY_NETWORK_INFO(string server, NetworkCredential credential = null)
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
                var smb2 = new Smb2Protocol(stream, server);

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
}
