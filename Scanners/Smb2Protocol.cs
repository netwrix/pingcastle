using PingCastle.Healthcheck;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using System.Text;

namespace PingCastle.Scanners
{
	public class Smb2Protocol
	{
		const int SMB2_NEGOTIATE = 0;
		const int SMB2_SESSION_SETUP = 1;

		const uint NTLMSSP_NEGOTIATE_56 = 0x80000000;
		const uint NTLMSSP_NEGOTIATE_NTLM = 0x200;

		const uint NTLMSSP_NEGOTIATE_SIGN = 0x10;
		const uint NTLMSSP_TARGET_TYPE_SERVER = 0x4;
		const uint NTLM_NEGOTIATE_OEM = 0x2;
		const uint NTLMSSP_NEGOTIATE_UNICODE = 0x1;
		//const uint NTLMSSP_NEGOTIATE_VERSION = 
		public const uint NTLM_V1 = NTLMSSP_NEGOTIATE_UNICODE + NTLM_NEGOTIATE_OEM + NTLMSSP_TARGET_TYPE_SERVER + NTLMSSP_NEGOTIATE_SIGN + NTLMSSP_NEGOTIATE_NTLM + NTLMSSP_NEGOTIATE_56;

		const uint STATUS_MORE_PROCESSING_REQUIRED = 0xc0000016;

		// https://msdn.microsoft.com/en-us/library/cc246529.aspx
		[StructLayout(LayoutKind.Explicit)]
		struct SMB2_Header
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
		struct SMB2_NegotiateRequest
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
		struct SMB2_NegotiateResponse
		{
			[FieldOffset(0)]
			public UInt16 StructureSize;
			[FieldOffset(2)]
			public byte SecurityMode;
			[FieldOffset(3)]
			public UInt16 Dialect;
		}

		[System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Portability", "CA1900:ValueTypeFieldsShouldBePortable"), StructLayout(LayoutKind.Explicit)]
		struct SMB2_SessionSetup
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

		[System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Portability", "CA1900:ValueTypeFieldsShouldBePortable"), StructLayout(LayoutKind.Explicit, CharSet = CharSet.Ansi)]
		struct NTLMSSP_NEGOTIATE
		{
			[FieldOffset(0)]
			[MarshalAsAttribute(UnmanagedType.ByValTStr, SizeConst = 8)]
			public string Signature;
			[FieldOffset(8)]
			public UInt32 MessageType;
			[FieldOffset(12)]
			public UInt32 NegotiateFlags;
			[FieldOffset(16)]
			public UInt16 DomainNameLen;
			[FieldOffset(18)]
			public UInt16 DomainNameMaxLen;
			[FieldOffset(20)]
			public UInt32 DomainNameBufferOffset;
			[FieldOffset(24)]
			public UInt16 WorkstationNameLen;
			[FieldOffset(26)]
			public UInt16 WorkstationNameMaxLen;
			[FieldOffset(28)]
			public UInt32 WorkstationNameBufferOffset;
			[FieldOffset(32)]
			public byte ProductMajorVersion;
			[FieldOffset(33)]
			public byte ProductMinorVersion;
			[FieldOffset(34)]
			public UInt16 ProductBuild;
			[FieldOffset(36)]
			public UInt16 reserved1;
			[FieldOffset(38)]
			public byte reserved2;
			[FieldOffset(39)]
			public byte NTLMRevisionCurrent;
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
		static byte[] GenerateSmb2HeaderFromCommand(byte command, ulong messageId = 0)
		{
			SMB2_Header header = new SMB2_Header();
			header.ProtocolId = 0x424D53FE;
			header.Command = command;
			header.StructureSize = 64;
			header.Command = command;
			header.MessageId = messageId;
			header.Reserved = 0xFEFF;
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

		// MS-SMB2  2.2.3 SMB2 NEGOTIATE Request
		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
		static byte[] GetNegotiateMessageSmbv2(int DialectToTest)
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
		static byte[] GetSessionSetupMessageSmbv2(int securityBufferLength)
		{
			var request = new SMB2_SessionSetup();
			request.StructureSize = 25;
			request.Flags = 0;
			request.SecurityMode = 2; // signing required
			request.Capabilities = 1; //DFS
			request.Channel = 0;
			request.PreviousSessionId = 0;
			request.SecurityBufferLength = (ushort) securityBufferLength;
			request.SecurityBufferOffset = (ushort) (Marshal.SizeOf(typeof(SMB2_SessionSetup)) + Marshal.SizeOf(typeof(SMB2_Header)));
			return getBytes(request);
		}

		static byte[] GetGSSSpNegoToken(int NTLMTokenLen)
		{
			// brutal ASN1 encoding - use https://lapo.it/asn1js to verify it
			return new byte[] 
			{
				0x60, (byte) (NTLMTokenLen + 32), 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02, 
				0xa0, (byte) (NTLMTokenLen + 22), 0x30, (byte) (NTLMTokenLen + 20), 0xa0, 0x0e, 0x30, 0x0c, 0x06, 0x0a,
				0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a, 
				0xa2, (byte) (NTLMTokenLen + 2), 0x04, (byte) NTLMTokenLen
			};
		}

		static byte[] GetNLTMSSP_NEGOTIATE(uint flags)
		{
			var message = new NTLMSSP_NEGOTIATE();
			message.Signature = "NTLMSSP";
			message.MessageType = 1;
			message.NegotiateFlags = flags;
			message.ProductMajorVersion = 10;
			message.ProductMinorVersion = 0;
			message.ProductBuild = 17134;
			message.NTLMRevisionCurrent = 15;
			return getBytes(message);
		}

		static byte[] BuildNegotiatePacket(int dialect)
		{
			byte[] header = GenerateSmb2HeaderFromCommand(SMB2_NEGOTIATE, 0);
			byte[] negotiatemessage = GetNegotiateMessageSmbv2(dialect);
			return BuildPacket(header, negotiatemessage);
		}

		static byte[] BuildSessionSetupPacket(uint flags)
		{
			byte[] header = GenerateSmb2HeaderFromCommand(SMB2_SESSION_SETUP, 1);
			byte[] NTLMSSPMessage = GetNLTMSSP_NEGOTIATE(flags);
			byte[] SpNegoToken = GetGSSSpNegoToken(NTLMSSPMessage.Length);
			byte[] message = GetSessionSetupMessageSmbv2(SpNegoToken.Length + NTLMSSPMessage.Length);
			return BuildPacket(header, message, SpNegoToken, NTLMSSPMessage);
		}

		static byte[] ReadPacket(Stream stream, string server)
		{
			byte[] netbios = new byte[4];
			if (stream.Read(netbios, 0, netbios.Length) != netbios.Length)
				throw new Smb2NotWellFormatedException(server);
			int size = netbios[0] << 24 | netbios[1] << 16 | netbios[2] << 8 | netbios[3] << 0;
			byte[] output = new byte[size];
			stream.Read(output, 0, size);
			return output;
		}

		static SMB2_Header ReadSMB2Header(byte[] packet)
		{
			GCHandle handle = GCHandle.Alloc(packet, GCHandleType.Pinned);
			SMB2_Header header = (SMB2_Header)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(SMB2_Header));
			handle.Free();
			return header;
		}

		static SMB2_NegotiateResponse ReadNegotiateResponse(byte[] packet)
		{
			GCHandle handle = GCHandle.Alloc(packet, GCHandleType.Pinned);
			SMB2_NegotiateResponse response = (SMB2_NegotiateResponse)Marshal.PtrToStructure(new IntPtr(handle.AddrOfPinnedObject().ToInt64() + Marshal.SizeOf(typeof(SMB2_Header))), typeof(SMB2_NegotiateResponse));
			handle.Free();
			return response;
		}

		static byte[] BuildPacket(params byte[][] bytes)
		{
			int size = 0;
			foreach (var array in bytes)
			{
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
				Array.Copy(array, 0, output, offset, array.Length);
				offset += array.Length;
			}
			return output;
		}

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
				byte[] packet = BuildNegotiatePacket(dialect);
				stream.Write(packet, 0, packet.Length);
				stream.Flush();

				byte[] answer = ReadPacket(stream, server);
				var header = ReadSMB2Header(answer);
				
				if (header.Status != 0)
				{
					Trace.WriteLine("Checking " + server + " for SMBV2 dialect 0x" + dialect.ToString("X2") + " = Not supported via error code");
					return false;
				}

				var negotiateresponse = ReadNegotiateResponse(answer);
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
		public static bool DoesServerSupportNTLMSSPFlagWithSmbV2(string server, uint flag)
		{
			Trace.WriteLine("Checking " + server + " for NTLM SSP flag 0x" + flag.ToString("X2"));
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
				byte[] packet = BuildNegotiatePacket(0x0202);
				stream.Write(packet, 0, packet.Length);
				stream.Flush();

				byte[] answer = ReadPacket(stream, server);
				var header = ReadSMB2Header(answer);

				if (header.Status != 0)
				{
					Trace.WriteLine("Error " + header.Status);
					return false;
				}

				packet = BuildSessionSetupPacket(flag);
				stream.Write(packet, 0, packet.Length);
				stream.Flush();

				answer = ReadPacket(stream, server);
				header = ReadSMB2Header(answer);
				if (header.Status != STATUS_MORE_PROCESSING_REQUIRED)
				{
					Trace.WriteLine("Error " + header.Status);
					return false;
				}
				// sadly I was hoping that NTLM v1 not supported will trigger an error message here.
				// but it triggers it after the challenge / response but STATUS_LOGON_FAILURE
				// it is not possible to make the difference between a wrong password and a NTLM v1 denied

				return false;
			}
			catch (Exception)
			{
				throw new Smb2NotSupportedException(server);
			}
		}
	}
}
