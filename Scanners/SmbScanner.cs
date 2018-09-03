//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.ADWS;
using PingCastle.Healthcheck;
using PingCastle.misc;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Security.Permissions;
using System.Text;
using System.Threading;

namespace PingCastle.Scanners
{
	[Serializable]
	public class SmbScannerException : Exception
	{
        public string Server { get; set; }

		public SmbScannerException(string server, string message) : base(message)
		{
			Server = server;
		}
		protected SmbScannerException(System.Runtime.Serialization.SerializationInfo info,
			System.Runtime.Serialization.StreamingContext context) : base(info, context) 
		{
			this.Server = info.GetString("Server");
		}

		[SecurityPermissionAttribute(SecurityAction.Demand, SerializationFormatter = true)]
		public override void GetObjectData(SerializationInfo info, StreamingContext context)
		{
			if (info == null)
			{
				throw new ArgumentNullException("info");
			}

			info.AddValue("Server", this.Server);

			// MUST call through to the base class to let it save its own state
			base.GetObjectData(info, context);
		}
	}

	[Serializable]
	public class SmbPortClosedException : SmbScannerException
	{
		public SmbPortClosedException(string server)
			: base(server, "The SMB port (tcp/445) is not open (" + server + ")")
		{
		}
	}

	[Serializable]
	public class Smb1NotSupportedException : SmbScannerException
	{
		public Smb1NotSupportedException(string server)
			: base(server, "The SMB v1 protocol is not supported (" + server + ")")
		{
		}
	}

	[Serializable]
	public class Smb2NotSupportedException : SmbScannerException
	{
		public Smb2NotSupportedException(string server)
			: base(server, "The SMB v2 protocol (also used in SMBv3) is not supported (" + server + ")")
		{
		}
	}
	
	public class SmbScanner : ScannerBase
	{

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Portability", "CA1900:ValueTypeFieldsShouldBePortable"), StructLayout(LayoutKind.Explicit)]
		struct SMB_Header {
			[FieldOffset(0)]
			public UInt32 Protocol;
			[FieldOffset(4)] 
			public byte Command;
			[FieldOffset(5)] 
			public int Status;
			[FieldOffset(9)] 
			public byte  Flags;
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
		// https://msdn.microsoft.com/en-us/library/cc246529.aspx
		[StructLayout(LayoutKind.Explicit)]
		struct SMB2_Header {
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

		const int SMB_COM_NEGOTIATE	= 0x72;
		const int SMB2_NEGOTIATE = 0;

		const int SMB_FLAGS_CASE_INSENSITIVE = 0x08;
		const int SMB_FLAGS_CANONICALIZED_PATHS = 0x10;

		const int SMB_FLAGS2_LONG_NAMES					= 0x0001;
		const int SMB_FLAGS2_EAS							= 0x0002;

		const int SMB_FLAGS2_SECURITY_SIGNATURE_REQUIRED	= 0x0010	;
		const int SMB_FLAGS2_IS_LONG_NAME					= 0x0040;

		const int SMB_FLAGS2_ESS							= 0x0800;

		const int SMB_FLAGS2_NT_STATUS					= 0x4000;
		const int SMB_FLAGS2_UNICODE						= 0x8000;

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

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
		static byte[] GenerateSmb2HeaderFromCommand(byte command)
		{
			SMB2_Header header = new SMB2_Header();
			header.ProtocolId = 0x424D53FE;
			header.Command = command;
			header.StructureSize = 64;
			header.Command = command;
			header.MessageId = 0;
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
			output[1] = (byte) dialect.Length;
			output[2] = 0;
			Array.Copy(dialect, 0, output, 3, dialect.Length);
			return output;
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
			request.DialectToTest = (UInt16) DialectToTest;
			return getBytes(request);
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
		public static bool DoesServerSupportDialect(string server, string dialect, out SMBSecurityModeEnum securityMode)
		{
			Trace.WriteLine("Checking " + server + " for SMBV1 dialect " + dialect);
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
					Trace.WriteLine("Checking " + server + " for SMBV1 dialect " + dialect + " = Supported");
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
				Trace.WriteLine("Checking " + server + " for SMBV1 dialect " + dialect + " = Not supported");
				return false;
			}
			catch (Exception)
			{
				throw new Smb1NotSupportedException(server);
			}
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
				byte[] header = GenerateSmb2HeaderFromCommand(SMB2_NEGOTIATE);
				byte[] negotiatemessage = GetNegotiateMessageSmbv2(dialect);
				byte[] packet = GetNegotiatePacket(header, negotiatemessage);
				stream.Write(packet, 0, packet.Length);
				stream.Flush();
				byte[] netbios = new byte[4];
                if (stream.Read(netbios, 0, netbios.Length) != netbios.Length)
                    return false;
				byte[] smbHeader = new byte[Marshal.SizeOf(typeof(SMB2_Header))];
				if (stream.Read(smbHeader, 0, smbHeader.Length) != smbHeader.Length)
                    return false;
				if (smbHeader[8] != 0 || smbHeader[9] != 0 || smbHeader[10] != 0 || smbHeader[11] != 0)
				{
					Trace.WriteLine("Checking " + server + " for SMBV1 dialect 0x" + dialect.ToString("X2") + " = Not supported via error code");
					return false;
				}
				byte[] negotiateresponse = new byte[6];
                if (stream.Read(negotiateresponse, 0, negotiateresponse.Length) != negotiateresponse.Length)
                    return false;
                int SmbSecurityMode = negotiateresponse[3] * 0x100 + negotiateresponse[2];
                if ((SmbSecurityMode & 1) != 0)
                {
                    securityMode = SMBSecurityModeEnum.SmbSigningEnabled;

                    if ((SmbSecurityMode & 2) != 0)
                    {
                        securityMode |= SMBSecurityModeEnum.SmbSigningRequired;
                    }
                }
                else
                {
                    securityMode = SMBSecurityModeEnum.None;
                }
                int selectedDialect = negotiateresponse[5] * 0x100 + negotiateresponse[4];
				if (selectedDialect == dialect)
				{
					Trace.WriteLine("Checking " + server + " for SMBV1 dialect 0x" + dialect.ToString("X2") + " = Supported");
					return true;
				}
				Trace.WriteLine("Checking " + server + " for SMBV1 dialect 0x" + dialect.ToString("X2") + " = Not supported via not returned dialect");
				return false;
			}
			catch (Exception)
			{
				throw new Smb2NotSupportedException(server);
			}
		}

		public static bool SupportSMB1(string server, out SMBSecurityModeEnum securityMode)
		{
            securityMode = SMBSecurityModeEnum.NotTested;
            try
			{
				return DoesServerSupportDialect(server, "NT LM 0.12", out securityMode);
			}
			catch (Exception)
			{
				return false;
			}
		}
        
		public static bool SupportSMB2And3(string server, out SMBSecurityModeEnum securityMode)
		{
			bool tempResult = false;
			bool result = false;
			securityMode = SMBSecurityModeEnum.NotTested;
			SMBSecurityModeEnum smbv2temp;
			foreach (int dialect in new int[] { 0x0202, 0x0210, 0x0300, 0x0302, 0x0311 })
			{
				try
				{
					tempResult = DoesServerSupportDialectWithSmbV2(server, dialect, out smbv2temp);
					if (tempResult)
					{
						result = true;
						securityMode = CombineSecurityMode(securityMode, smbv2temp);
					}
				}
				catch (Exception)
				{
				}
			}
			return result;
		}

		public override string Name { get { return "smb"; } }
		public override string Description { get { return "Scan a computer and determiner the smb version available. Also if SMB signing is active."; } }

		override protected string GetCsvHeader()
		{
			return "Computer\tSMB Port Open\tSMB1(NT LM 0.12)\tSMB1 Sign Required\tSMB2(0x0202)\tSMB2(0x0210)\tSMB3(0x0300)\tSMB3(0x0302)\tSMB3(0x0311)\tSMB2 Sign Required";
		}

		override protected string GetCsvData(string computer)
		{
			bool isPortOpened = true;
			bool SMBv1 = false;
			bool SMBv2_0x0202 = false;
			bool SMBv2_0x0210 = false;
			bool SMBv2_0x0300 = false;
			bool SMBv2_0x0302 = false;
			bool SMBv2_0x0311 = false;
            SMBSecurityModeEnum smbv1secmode = SMBSecurityModeEnum.NotTested;
            SMBSecurityModeEnum smbv2secmode = SMBSecurityModeEnum.NotTested;
			SMBSecurityModeEnum smbv2temp;
            try
			{
				try
				{
					SMBv1 = DoesServerSupportDialect(computer, "NT LM 0.12", out smbv1secmode);
				}
				catch (Smb1NotSupportedException)
				{
				}
				try
				{
					SMBv2_0x0202 = DoesServerSupportDialectWithSmbV2(computer, 0x0202, out smbv2secmode);
					SMBv2_0x0210 = DoesServerSupportDialectWithSmbV2(computer, 0x0210, out smbv2temp);
					smbv2secmode = CombineSecurityMode(smbv2secmode, smbv2temp);
					SMBv2_0x0300 = DoesServerSupportDialectWithSmbV2(computer, 0x0300, out smbv2temp);
					smbv2secmode = CombineSecurityMode(smbv2secmode, smbv2temp);
					SMBv2_0x0302 = DoesServerSupportDialectWithSmbV2(computer, 0x0302, out smbv2temp);
					smbv2secmode = CombineSecurityMode(smbv2secmode, smbv2temp);
					SMBv2_0x0311 = DoesServerSupportDialectWithSmbV2(computer, 0x0311, out smbv2temp);
					smbv2secmode = CombineSecurityMode(smbv2secmode, smbv2temp);
				}
				catch (Smb2NotSupportedException)
				{
				}
			}
			catch (SmbPortClosedException)
			{
				isPortOpened = false;
			}
			return computer + "\t" + (isPortOpened ? "Yes" : "No") + "\t" + (SMBv1 ? "Yes" : "No")
                                                            + "\t" + ((smbv1secmode & SMBSecurityModeEnum.SmbSigningRequired) != 0 ? "Yes" : "No")
                                                            + "\t" + (SMBv2_0x0202 ? "Yes" : "No")
															+ "\t" + (SMBv2_0x0210 ? "Yes" : "No")
															+ "\t" + (SMBv2_0x0300 ? "Yes" : "No")
															+ "\t" + (SMBv2_0x0302 ? "Yes" : "No")
															+ "\t" + (SMBv2_0x0311 ? "Yes" : "No")
                                                            + "\t" + ((smbv2secmode & SMBSecurityModeEnum.SmbSigningRequired) != 0 ? "Yes" : "No");
		}

		private static SMBSecurityModeEnum CombineSecurityMode(SMBSecurityModeEnum smbv2secmode, SMBSecurityModeEnum smbv2temp)
		{
			if (smbv2temp == SMBSecurityModeEnum.NotTested)
				return smbv2secmode;
			if (smbv2secmode == SMBSecurityModeEnum.NotTested)
				return smbv2temp;
			if (smbv2temp == SMBSecurityModeEnum.None || smbv2secmode == SMBSecurityModeEnum.None)
				return SMBSecurityModeEnum.None;
			if ((smbv2temp & SMBSecurityModeEnum.SmbSigningEnabled) != 0 && (smbv2secmode & SMBSecurityModeEnum.SmbSigningEnabled) != 0)
			{
				if ((smbv2temp & SMBSecurityModeEnum.SmbSigningRequired) != 0 && (smbv2secmode & SMBSecurityModeEnum.SmbSigningRequired) != 0)
				{
					return SMBSecurityModeEnum.SmbSigningEnabled | SMBSecurityModeEnum.SmbSigningRequired;
				}
				return SMBSecurityModeEnum.SmbSigningEnabled;
			}
			// defensive programming
			return SMBSecurityModeEnum.NotTested;
		}
		
	}
}
