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
using static PingCastle.Scanners.Smb2Protocol;

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
        public const int STATUS_NOT_SUPPORTED = unchecked((int)0xC00000BB);

        // Enums for SMB protocol constants
        [Flags]
        public enum SMB2_NEGOTIATE_CONTEXT_TYPES : ushort
        {
            SMB2_PREAUTH_INTEGRITY_CAPABILITIES = 0x0001,
            SMB2_ENCRYPTION_CAPABILITIES = 0x0002,
            SMB2_COMPRESSION_CAPABILITIES = 0x0003,
            SMB2_NETNAME_NEGOTIATE_CONTEXT_ID = 0x0005,
            SMB2_TRANSPORT_CAPABILITIES = 0x0006,
            SMB2_RDMA_TRANSFORM_CAPABILITIES = 0x0007,
            SMB2_SIGNING_CAPABILITIES = 0x0008,
            SMB2_CONTEXTTYPE_RESERVED = 0x0100
        }

        [Flags]
        public enum SMB2_CAPABILITIES : uint
        {
            SMB2_GLOBAL_CAP_DFS = 0x00000001,
            SMB2_GLOBAL_CAP_LEASING = 0x00000002,
            SMB2_GLOBAL_CAP_LARGE_MTU = 0x00000004,
            SMB2_GLOBAL_CAP_MULTI_CHANNEL = 0x00000008,
            SMB2_GLOBAL_CAP_PERSISTENT_HANDLES = 0x00000010,
            SMB2_GLOBAL_CAP_DIRECTORY_LEASING = 0x00000020,
            SMB2_GLOBAL_CAP_ENCRYPTION = 0x00000040,
            SMB2_GLOBAL_CAP_NOTIFICATIONS = 0x00000080
        }

        [Flags]
        public enum SMB2_SECURITY_MODE : ushort
        {
            SMB2_NEGOTIATE_SIGNING_ENABLED = 0x0001,
            SMB2_NEGOTIATE_SIGNING_REQUIRED = 0x0002
        }

        // For PreAuth Integrity Hash Algorithm IDs
        public enum SMB2_HASH_ALGORITHM : ushort
        {
            SMB2_SHA_512 = 0x0001
        }

        // For Encryption Algorithm IDs
        public enum SMB2_ENCRYPTION_ALGORITHM : ushort
        {
            SMB2_ENCRYPTION_AES128_CCM = 0x0001,
            SMB2_ENCRYPTION_AES128_GCM = 0x0002,
            SMB2_ENCRYPTION_AES256_CCM = 0x0003,
            SMB2_ENCRYPTION_AES256_GCM = 0x0004
        }

        // For Dialect values
        public enum SMB2_DIALECTS : ushort
        {
            SMB2_DIALECT_2_0_2 = 0x0202,
            SMB2_DIALECT_2_1 = 0x0210,
            SMB2_DIALECT_3_0 = 0x0300,
            SMB2_DIALECT_3_0_2 = 0x0302,
            SMB2_DIALECT_3_1_1 = 0x0311
        }

        // Updated struct to support SMB 3.1.1 negotiate contexts
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Portability", "CA1900:ValueTypeFieldsShouldBePortable"), StructLayout(LayoutKind.Explicit)]
        public struct SMB2_NegotiateRequest
        {
            [FieldOffset(0)]
            public ushort StructureSize;
            [FieldOffset(2)]
            public ushort DialectCount;
            [FieldOffset(4)]
            public ushort SecurityMode;
            [FieldOffset(6)]
            public ushort Reserved;
            [FieldOffset(8)]
            public uint Capabilities;
            [FieldOffset(12)]
            public Guid ClientGuid;
            // This field is a union - either ClientStartTime or NegotiateContext fields
            [FieldOffset(28)]
            public uint NegotiateContextOffset;
            [FieldOffset(32)]
            public ushort NegotiateContextCount;
            [FieldOffset(34)]
            public ushort Reserved2;
            // Used for non-SMB 3.1.1 dialects
            [FieldOffset(28)]
            public ulong ClientStartTime;
            [FieldOffset(36)]
            public ushort DialectToTest; // First dialect in the Dialects array
        }

        // Structure for negotiate contexts
        [StructLayout(LayoutKind.Sequential)]
        public struct SMB2_NEGOTIATE_CONTEXT
        {
            public SMB2_NEGOTIATE_CONTEXT_TYPES ContextType;
            public UInt16 DataLength;
            public UInt32 Reserved;
        }

        // Methods for building SMB 3.1.1 negotiate packets
        public byte[] BuildNegotiatePacket(int dialect)
        {
            byte[] header = GenerateSmb2HeaderFromCommand(SBM2_Command.SMB2_NEGOTIATE);
            byte[] message = GetNegotiateMessageSmbv2(dialect);

            // Combine header and message
            byte[] packet = BuildPacket(header, message);
            return packet;
        }

        // MS-SMB2  2.2.3 SMB2 NEGOTIATE Request
        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        public byte[] GetNegotiateMessageSmbv2(int DialectToTest)
        {
            SMB2_NegotiateRequest request = new SMB2_NegotiateRequest
            {
                StructureSize = 36,
                DialectCount = 1,
                SecurityMode = (ushort)SMB2_SECURITY_MODE.SMB2_NEGOTIATE_SIGNING_ENABLED,
                Reserved = 0,
                ClientGuid = Guid.NewGuid(),
                DialectToTest = (UInt16)DialectToTest
            };

            // Set capabilities based on dialect
            if (DialectToTest >= (int)SMB2_DIALECTS.SMB2_DIALECT_3_0)
            {
                request.Capabilities = (UInt32)(
                    SMB2_CAPABILITIES.SMB2_GLOBAL_CAP_DFS |
                    SMB2_CAPABILITIES.SMB2_GLOBAL_CAP_LEASING |
                    SMB2_CAPABILITIES.SMB2_GLOBAL_CAP_LARGE_MTU);

                if (DialectToTest >= (int)SMB2_DIALECTS.SMB2_DIALECT_3_1_1)
                {
                    request.Capabilities |= (UInt32)(
                        SMB2_CAPABILITIES.SMB2_GLOBAL_CAP_DIRECTORY_LEASING |
                        SMB2_CAPABILITIES.SMB2_GLOBAL_CAP_ENCRYPTION);
                }
            }
            else
            {
                request.Capabilities = (UInt32)SMB2_CAPABILITIES.SMB2_GLOBAL_CAP_DFS;
            }

            // For SMB 3.1.1 (0x0311), we need to add NegotiateContexts
            if (DialectToTest == (int)SMB2_DIALECTS.SMB2_DIALECT_3_1_1)
            {
                // Set NegotiateContext fields
                request.NegotiateContextCount = 2; // We'll add Preauth and Encryption contexts
                request.Reserved2 = 0;

                // Create the base negotiate request byte array (includes one dialect)
                int baseSize = Marshal.SizeOf(typeof(SMB2_NegotiateRequest));

                // Calculate the NegotiateContextOffset
                // SMB2 header (64 bytes) + base request (36 bytes) + dialects (2 bytes per dialect) + padding
                int headerSize = 64; // Size of SMB2_Header
                int sizeBeforeContext = headerSize + baseSize;
                // Add padding to align to 8 byte boundary
                int padding = CalculatePadding(sizeBeforeContext);
                int contextOffset = sizeBeforeContext + padding;

                // Update the offset in our request
                request.NegotiateContextOffset = (UInt32)contextOffset;

                // Build the complete packet
                var baseRequest = StructureToByteArray(request);
                var fullRequest = new List<byte>(baseRequest);

                ApplyPadding(fullRequest, padding);

                // Add PREAUTH_INTEGRITY_CAPABILITIES context
                SMB2_NEGOTIATE_CONTEXT preAuthContext = new SMB2_NEGOTIATE_CONTEXT();
                preAuthContext.ContextType = SMB2_NEGOTIATE_CONTEXT_TYPES.SMB2_PREAUTH_INTEGRITY_CAPABILITIES;
                preAuthContext.DataLength = 38; // HashAlgorithmCount(2) + SaltLength(2) + HashAlgorithm(2) + SaltData(32)
                preAuthContext.Reserved = 0;

                byte[] preAuthContextHeader = StructureToByteArray(preAuthContext);
                fullRequest.AddRange(preAuthContextHeader);

                // Create preauth integrity data with salt
                var preAuthData = new List<byte>();

                // Add preauth integrity data - use explicit cast to get the underlying ushort value
                preAuthData.AddRange(new byte[] {
                    0x01, 0x00, // HashAlgorithmCount = 1
                    0x20, 0x00, // SaltLength = 32 (changed from 0x00, 0x00)
                    (byte)((ushort)SMB2_HASH_ALGORITHM.SMB2_SHA_512 & 0xFF),
                    (byte)((ushort)SMB2_HASH_ALGORITHM.SMB2_SHA_512 >> 8)
                });

                // Generate cryptographically secure salt
                byte[] salt = new byte[32];
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(salt);
                }

                preAuthData.AddRange(salt);

                fullRequest.AddRange(preAuthData);

                // Pad to next 8-byte boundary
                int nextPadding = CalculatePadding(fullRequest.Count);
                ApplyPadding(fullRequest, nextPadding);

                // Add ENCRYPTION_CAPABILITIES context
                SMB2_NEGOTIATE_CONTEXT encryptContext = new SMB2_NEGOTIATE_CONTEXT();
                encryptContext.ContextType = SMB2_NEGOTIATE_CONTEXT_TYPES.SMB2_ENCRYPTION_CAPABILITIES;
                encryptContext.DataLength = 4; // CipherCount(2) + Ciphers(2)
                encryptContext.Reserved = 0;

                byte[] encryptContextHeader = StructureToByteArray(encryptContext);
                fullRequest.AddRange(encryptContextHeader);

                // Add encryption capabilities data - use explicit cast to get the underlying ushort value
                byte[] encryptData = new byte[] {
                    0x01, 0x00, // CipherCount = 1
                    (byte)((ushort)SMB2_ENCRYPTION_ALGORITHM.SMB2_ENCRYPTION_AES128_GCM & 0xFF),
                    (byte)((ushort)SMB2_ENCRYPTION_ALGORITHM.SMB2_ENCRYPTION_AES128_GCM >> 8)  // Ciphers[0] = AES-128-GCM (0x0002)
                };

                fullRequest.AddRange(encryptData);

                return fullRequest.ToArray();
            }
            else
            {
                // For pre-SMB 3.1.1 dialects, use the simple approach
                request.ClientStartTime = 0;
                return StructureToByteArray(request);
            }
        }

        private static void ApplyPadding(List<byte> request, int padding)
        {
            for (int i = 0; i < padding; i++)
            {
                request.Add(0);
            }
        }

        private static int CalculatePadding(int length)
        {
            return (8 - (length % 8)) % 8;
        }

        // Helper method to convert a structure to a byte array
        private byte[] StructureToByteArray<T>(T structure) where T : struct
        {
            int size = Marshal.SizeOf(structure);
            byte[] arr = new byte[size];
            IntPtr ptr = Marshal.AllocHGlobal(size);

            try
            {
                Marshal.StructureToPtr(structure, ptr, true);
                Marshal.Copy(ptr, arr, 0, size);
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }

            return arr;
        }

        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        public byte[] GenerateSmb2HeaderFromCommand(SBM2_Command command)
        {
            SMB2_Header header = new SMB2_Header();
            header.ProtocolId = 0x424D53FE;
            header.Command = (UInt16)command;  // Cast to UInt16 instead of byte
            header.StructureSize = 64;
            header.MessageId = _messageId++;
            header.Reserved = 0xFEFF;
            header.SessionId = _sessionid;
            header.TreeId = _TreeId;
            return getBytes(header);
        }

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
        public struct SMB2_NegotiateResponse
        {
            [FieldOffset(0)]
            public UInt16 StructureSize;
            [FieldOffset(2)]
            public UInt16 SecurityMode;
            [FieldOffset(4)]
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
            int bytesRead = 0;
            int totalRead = 0;

            // Read the full NetBIOS header (4 bytes)
            while (totalRead < 4)
            {
                bytesRead = _stream.Read(netbios, totalRead, netbios.Length - totalRead);
                if (bytesRead == 0)
                    throw new IOException("Connection closed by remote host");
                totalRead += bytesRead;
            }

            // NetBIOS header format: first byte is message type, next 3 bytes are length
            int size = ((netbios[1] & 0xFF) << 16) | ((netbios[2] & 0xFF) << 8) | (netbios[3] & 0xFF);

            if (size == 0)
                return new byte[0];

            byte[] output = new byte[size];
            totalRead = 0;

            // Read the entire message
            while (totalRead < size)
            {
                bytesRead = _stream.Read(output, totalRead, size - totalRead);
                if (bytesRead == 0)
                    throw new IOException("Connection closed while reading message body");
                totalRead += bytesRead;
            }

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

            // NetBIOS header: 4 bytes for size (size is the length WITHOUT the 4-byte header)
            byte[] output = new byte[size + 4];

            // NetBIOS message header (first byte should be 0 for regular message)
            output[0] = 0;

            // Size in NetBIOS format (the 3 remaining bytes represent the size)
            if (size > 0xFFFFFF)
            {
                throw new InvalidOperationException("SMB message too large");
            }

            output[1] = (byte)((size >> 16) & 0xFF);  // Most significant byte
            output[2] = (byte)((size >> 8) & 0xFF);   // Middle byte
            output[3] = (byte)(size & 0xFF);          // Least significant byte

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
            Trace.WriteLine(LogPrefix + "Negotiate Packet sent");

            byte[] answer = ReadPacket();
            Trace.WriteLine(LogPrefix + "Negotiate Packet received");
            var header = ReadSMB2Header(answer);

            if (header.Status != 0)
            {
                Trace.WriteLine(LogPrefix + "Checking " + _server + " for SMBV2 dialect 0x" + dialect.ToString("X2") + " = Not supported via error code");
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

                Trace.WriteLine(LogPrefix + "SessionSetup Packet sent");
                var answer = ReadPacket();
                var header = ReadSMB2Header(answer);
                Trace.WriteLine(LogPrefix + "SessionSetup Packet received");
                if (header.Status == 0)
                {
                    return ReadResponse<SMB2_SessionSetupResponse>(answer);
                }
                if (header.Status != STATUS_MORE_PROCESSING_REQUIRED)
                {
                    Trace.WriteLine(LogPrefix + "Checking " + _server + "Error " + header.Status);
                    throw new Win32Exception((int)header.Status);
                }
                if (!bContinueProcessing)
                {
                    Trace.WriteLine(LogPrefix + "Checking " + _server + "Error " + header.Status + " when no processing needed");
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

            Trace.WriteLine(LogPrefix + "TreeConnect Packet sent");
            var answer = ReadPacket();
            var header = ReadSMB2Header(answer);
            Trace.WriteLine(LogPrefix + "TreeConnect Packet received");
            if (header.Status != 0)
            {
                Trace.WriteLine(LogPrefix + "Checking " + _server + "Error " + header.Status);
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

            Trace.WriteLine(LogPrefix + "IOCTLRequest Packet sent");
            var answer = ReadPacket();
            var header = ReadSMB2Header(answer);
            Trace.WriteLine(LogPrefix + "IOCTLRequest Packet received");
            if (header.Status != 0)
            {
                Trace.WriteLine(LogPrefix + "Checking " + _server + "Error " + header.Status);
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



        public string LogPrefix { get; set; }
    }
    public class Smb2ProtocolTest
    {
        [SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        public static bool DoesServerSupportDialectWithSmbV2(string server, int dialect, out SMBSecurityModeEnum securityMode, string logPrefix = null)
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

                var smb2 = new Smb2Protocol(stream, server);
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

                if (dialect == (int)SMB2_DIALECTS.SMB2_DIALECT_3_1_1)
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
