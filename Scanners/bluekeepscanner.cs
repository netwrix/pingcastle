//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
/*
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace PingCastle.Scanners
{
	public class bluekeepscanner : ScannerBase
	{
		public override string Name { get { return "bluekeep"; } }
		public override string Description { get { return "Check for the bluekeep vulnerability without exploiting it. Beware that it may trigger AV response by closing the connection"; } }
        
		override protected string GetCsvHeader()
		{
			return "Computer\tWas tested\tVulnerable";
		}

		override protected string GetCsvData(string computer)
		{
			bool isTested = false;
			bool isVulnerable = false;
			try
			{
				isVulnerable = ScanForBlueKeep(computer);
				isTested = true;
			}
			catch (Exception)
			{
			}
			return computer + "\t" + (isTested ? "Yes" : "No") + "\t" + (isVulnerable ? "Yes" : "No");
		}

		static public bool ScanForBlueKeep(string computer)
		{
			Trace.WriteLine("Checking " + computer + " for bluekeep");
			TcpClient client = new TcpClient();
			try
			{
				client.Connect(computer, 3389);
				
				
			}
			catch (Exception)
			{
				throw new Exception("RDP port closed " + computer);
			}
			try
			{
				NetworkStream stream = client.GetStream();

				// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/18a27ef9-6f9a-4501-b000-94b1fe3c2c10
				Console.WriteLine("-> Client X.224 Connection Request PDU");
				SendPacket(x224ConnectionRequest("elton"), stream);

				// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/13757f8f-66db-4273-9d2c-385c33b1e483
				byte[] inbuffer = ReadTPKT(stream);
				Console.WriteLine("<- Server X.224 Connection Confirm PDU");

				// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/db6713ee-1c0e-4064-a3b3-0fac30b4037b
				Console.WriteLine("-> Client MCS Connect Initial PDU with GCC Conference Create Request");
				SendPacket(ConnectInitial("eltons-dev"), stream);

				// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/927de44c-7fe8-4206-a14f-e5517dc24b1c
				inbuffer = ReadTPKT(stream);
				Console.WriteLine("<- Server MCS Connect Response PDU with GCC Conference Create Response");
				
				byte[] rsmod;
				byte[] rsexp;
				byte[] server_random;
				int bitlen;
				ParseServerData(inbuffer, out rsmod, out rsexp, out server_random, out bitlen);

				// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/04c60697-0d9a-4afd-a0cd-2cc133151a9c
				Console.WriteLine("-> Client MCS Erect Domain Request PDU");
				SendPacket(new byte[] { 0x02, 0xf0, 0x80, 0x04, 0x00, 0x01, 0x00, 0x01 }, stream);
				
				// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/f5d6a541-9b36-4100-b78f-18710f39f247
				Console.WriteLine("-> Client MCS Attach User Request PDU");
				SendPacket(new byte[] { 0x02, 0xf0, 0x80, 0x28 }, stream);

				// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/3b3d850b-99b1-4a9a-852b-1eb2da5024e5
				inbuffer = ReadTPKT(stream);
				Console.WriteLine("<- Server MCS Attach User Confirm PDU (len=" + inbuffer.Length + ")");

				int user1= inbuffer[5] + inbuffer[6];
				
				// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/64564639-3b2d-4d2c-ae77-1105b4cc011b
				byte[] pdu_channel_request = new byte[] {0x02,0xf0,0x80,0x38, 0, 0, 3, 0};
				pdu_channel_request[pdu_channel_request.Length - 3] = (byte)user1;

				Console.WriteLine("-> Client MCS Channel Join Request PDU");
				pdu_channel_request[pdu_channel_request.Length - 1] = (byte)0xF1;
				SendPacket(pdu_channel_request, stream);

				inbuffer = ReadTPKT(stream);
				Console.WriteLine("<- Server MCS Channel Join Confirm PDU Received (len=" + inbuffer.Length + ")");

				Console.WriteLine("-> Client MCS Channel Join Request PDU");
				pdu_channel_request[pdu_channel_request.Length - 1] = (byte)0xEB;
				SendPacket(pdu_channel_request, stream); 

				inbuffer = ReadTPKT(stream);
				Console.WriteLine("<- Server MCS Channel Join Confirm PDU Received (len=" + inbuffer.Length + ")");

				Console.WriteLine("-> Client MCS Channel Join Request PDU");
				pdu_channel_request[pdu_channel_request.Length - 1] = (byte)0xEC;
				SendPacket(pdu_channel_request, stream); 

				inbuffer = ReadTPKT(stream);
				Console.WriteLine("<- Server MCS Channel Join Confirm PDU Received (len=" + inbuffer.Length + ")");

				Console.WriteLine("-> Client MCS Channel Join Request PDU");
				pdu_channel_request[pdu_channel_request.Length - 1] = (byte)0xED;
				SendPacket(pdu_channel_request, stream);

				inbuffer = ReadTPKT(stream);
				Console.WriteLine("<- Server MCS Channel Join Confirm PDU Received (len=" + inbuffer.Length + ")");

				Console.WriteLine("-> Client MCS Channel Join Request PDU");
				pdu_channel_request[pdu_channel_request.Length - 1] = (byte)0xEF;
				SendPacket(pdu_channel_request, stream);

				inbuffer = ReadTPKT(stream);
				Console.WriteLine("<- Server MCS Channel Join Confirm PDU Received (len=" + inbuffer.Length + ")");

				Console.WriteLine("-> Client MCS Channel Join Request PDU");
				pdu_channel_request[pdu_channel_request.Length - 1] = (byte)0xF0;
				SendPacket(pdu_channel_request, stream);

				inbuffer = ReadTPKT(stream);
				Console.WriteLine("<- Server MCS Channel Join Confirm PDU Received (len=" + inbuffer.Length + ")");

				// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/9cde84cd-5055-475a-ac8b-704db419b66f
				Console.WriteLine("-> Client Security Exchange PDU");

				byte[] clientrand = new byte[32] {
												0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 
												0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 
												0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 
												0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
				};

				SendPacket(SecuritExchange(clientrand, rsexp, rsmod, bitlen), stream);
				
				byte[] clientEncryptKey, clientDecryptKey, macKey, sessionKeyBlob;
				ComputeRC4Keys(clientrand, server_random, out clientEncryptKey, out clientDecryptKey, out macKey, out sessionKeyBlob);

				RDP_RC4 encrypt = new RDP_RC4(clientEncryptKey);

				// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/772d618e-b7d6-4cd0-b735-fa08af558f9d
				Console.WriteLine("-> Client Info PDU");
				SendPacket(EncryptPkt(ConvertHexStringToByteArray(GetClientInfo()), encrypt, macKey, 0x48), stream);

				// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/7d941d0d-d482-41c5-b728-538faa3efb31
				inbuffer = ReadTPKT(stream);
				Console.WriteLine("<- Server License Error PDU - Valid Client (len=" + inbuffer.Length + ")");

				// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/a07abad1-38bb-4a1a-96c9-253e3d5440df
				inbuffer = ReadTPKT(stream);
				Console.WriteLine("<- Demand Active PDU (len=" + inbuffer.Length + ")");

				// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/4c3c2710-0bf0-4c54-8e69-aff40ffcde66
				Console.WriteLine("-> Client Confirm Active PDU");
				SendPacket(EncryptPkt(ConvertHexStringToByteArray(ConfirmActive()), encrypt, macKey, 0x38), stream);

				// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/e0027486-f99a-4f0f-991c-eda3963521c2
				Console.WriteLine("-> client synchronize PDU");
				SendPacket(EncryptPkt(ConvertHexStringToByteArray("16001700f103ea030100000108001f0000000100ea03"), encrypt, macKey), stream);

				// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/9d1e1e21-d8b4-4bfd-9caf-4b72ee91a713
				Console.WriteLine("-> client control cooperate PDU");
				SendPacket(EncryptPkt(ConvertHexStringToByteArray("1a001700f103ea03010000010c00140000000400000000000000"), encrypt, macKey), stream);

				// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/4f94e123-970b-4242-8cf6-39820d8e3d35
				Console.WriteLine("-> client control request control PDU");
				SendPacket(EncryptPkt(ConvertHexStringToByteArray("1a001700f103ea03010000010c00140000000100000000000000"), encrypt, macKey), stream);

				// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/2d122191-af10-4e36-a781-381e91c182b7
				Console.WriteLine("-> client persistent key list PDU");
				SendPacket(EncryptPkt(ConvertHexStringToByteArray(ClientPersistentKeyList()), encrypt, macKey, 0x38), stream);

				// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/7067da0d-e318-4464-88e8-b11509cf0bd9
				Console.WriteLine("-> client font list PDU");
				SendPacket(EncryptPkt(ConvertHexStringToByteArray("1a001700f103ea03010000010c00270000000000000003003200"), encrypt, macKey), stream);

				// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/5186005a-36f5-4f5d-8c06-968f28e2d992
				inbuffer = ReadTPKT(stream);
				Console.WriteLine("<- Server Synchronize PDU (len=" + inbuffer.Length + ")");

				// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/43296a04-6324-4cbf-93d1-8e056e969082
				inbuffer = ReadTPKT(stream);
				Console.WriteLine("<- Server Control PDU - Cooperate (len=" + inbuffer.Length + ")");

				// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/ff7bae0e-cd13-4776-83b2-ef1f45e1fc41
				inbuffer = ReadTPKT(stream);
				Console.WriteLine("<- Server Control PDU - Granted Control (len=" + inbuffer.Length + ")");

				// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/7ba6ba81-e4f4-46a7-9062-2d57a821be26
				inbuffer = ReadTPKT(stream);
				Console.WriteLine("<- Server Font Map PDU (len=" + inbuffer.Length + ")");

				Console.WriteLine("clear buffer");
				byte[] temp = ReadAllAvailableData(stream);

				byte[] disconnect = new byte[] { 0x03, 0x00, 0x00, 0x09, 0x02, 0xf0, 0x80, 0x21, 0x80 };

				for (int k = 0; k < 4; k++)
				{
					SendPacket(EncryptPkt(ConvertHexStringToByteArray("100000000300000000000000020000000000000000000000"), encrypt, macKey, 8, 0x3ed), stream);

					SendPacket(EncryptPkt(ConvertHexStringToByteArray("20000000030000000000000000000000020000000000000000000000000000000000000000000000"), encrypt, macKey, 8, 0x3ed), stream);
					inbuffer = ReadAllAvailableData(stream);
					if (inbuffer.Length >= disconnect.Length)
					{
						bool match = true;
						for (int j = 0; j < inbuffer.Length; j++)
						{
							if (inbuffer[inbuffer.Length - disconnect.Length + j] != disconnect[j])
							{
								match = false;
								break;
							}
						}
						if (match)
						{
							Console.WriteLine("disconnect found - machine is vulnerable");
							return true;
						}
					}
				}
			}
			catch (Exception)
			{
				throw;
			}
			return false;
		}

		// T.123 - 8. Packet header to delimit data units in an octet stream
		private static byte[] ReadTPKT(Stream stream)
		{
			byte[] inbuffer = new byte[65535];
			if (!stream.CanRead)
			{
				throw new InvalidOperationException("no read");
			}
			int bytesRead = stream.Read(inbuffer, 0, 4);
			if (bytesRead != 4)
			{
				throw new InvalidOperationException("incomplete packet");
			}
			if (inbuffer[0] != 3)
			{
				throw new InvalidOperationException("invalid signature");
			}
			if (inbuffer[1] != 0)
			{
				throw new InvalidOperationException("invalid reserved byte");
			}
			int lenght = inbuffer[2] * 0x100 + inbuffer[3] - 4;
			bytesRead = stream.Read(inbuffer, 0, lenght);
			if (bytesRead < lenght)
			{
				throw new InvalidOperationException("data too short");
			}
			byte[] output = new byte[lenght];
			Array.Copy(inbuffer, output, lenght);
			return output;
		}

		static byte[] ReadAllAvailableData(Stream stream)
		{
			byte[] inbuffer = new byte[65535];
			if (!stream.CanRead)
			{
				throw new InvalidOperationException("no read");
			}
			int lenght = stream.Read(inbuffer, 0, inbuffer.Length);
			byte[] output = new byte[lenght];
			Array.Copy(inbuffer, output, lenght);
			return output;
		}

		private static void SendPacket(byte[] data, Stream stream)
		{
			byte[] output = new byte[data.Length + 4];
			output[0] = 3;
			output[1] = 0;
			output[2] = (byte) ((data.Length + 4) / 0x100);
			output[3] = (byte) ((data.Length + 4) % 0x100);
			Array.Copy(data, 0, output, 4, data.Length);
			stream.Write(output, 0, output.Length);
			stream.Flush();
		}

		private static string GetClientInfo()
		{
			string data = "000000003301000000000a000000000000000000";
			data+="75007300650072003000"; // FIXME: username
			data+="000000000000000002001c00";
			data+="3100390032002e003100360038002e0031002e00320030003800"; // FIXME: ip
			data+="00003c0043003a005c00570049004e004e0054005c00530079007300740065006d00330032005c006d007300740073006300610078002e0064006c006c000000a40100004700540042002c0020006e006f0072006d0061006c0074006900640000000000000000000000000000000000000000000000000000000000000000000000000000000a00000005000300000000000000000000004700540042002c00200073006f006d006d006100720074006900640000000000000000000000000000000000000000000000000000000000000000000000000000000300000005000200000000000000c4ffffff00000000270000000000";
			return data;
		}

		private static string ConfirmActive()
		{
			string data = "a4011300f103ea030100ea0306008e014d53545343000e00000001001800010003000002000000000d04000000000000000002001c00100001000100010020035802000001000100000001000000030058000000000000000000000000000000000000000000010014000000010047012a000101010100000000010101010001010000000000010101000001010100000000a1060000000000000084030000000000e40400001300280000000003780000007800000050010000000000000000000000000000000000000000000008000a000100140014000a0008000600000007000c00000000000000000005000c00000000000200020009000800000000000f000800010000000d005800010000000904000004000000000000000c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c000800010000000e0008000100000010003400fe000400fe000400fe000800fe000800fe001000fe002000fe004000fe008000fe000001400000080001000102000000";
			return data;
		}


		private static string ClientPersistentKeyList()
		{
			string data = "49031700f103ea03010000013b031c00000001000000000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
			return data;
		}

		private static byte[] ConvertHexStringToByteArray(string data)
		{
			int length = (data.Length) / 2;
			byte[] arr1 = new byte[length];
			for (int i = 0; i < length; i++)
				arr1[i] = Convert.ToByte(data.Substring(2 * i, 2), 16);
			return arr1;
		}

		// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/18a27ef9-6f9a-4501-b000-94b1fe3c2c10
		private static byte[] x224ConnectionRequest(string username)
		{
			MemoryStream ms = new MemoryStream();
			BinaryReader reader = new BinaryReader(ms);
			byte[] b = Encoding.UTF8.GetBytes(username);
			byte[] part1 = new byte[] {
				(byte) (33+b.Length), // X.224: Length indicator
				0xe0,                                  // X.224: Type - TPDU
				0x00,0x00,                              // X.224: Destination reference
				0x00,0x00,                              // X.224: Source reference
				0x00,                                  // X.224: Class and options
				0x43,0x6f,0x6f,0x6b,0x69,0x65,0x3a,0x20,0x6d,0x73,0x74,0x73,0x68,0x61,0x73,0x68,0x3d, // "Cookie: mstshash=
			};
			byte[] part2 = new byte[] {
				0x0d,0x0a,                              // Cookie terminator sequence
				0x01,                                  // Type: RDP_NEG_REQ)
				0x00,                                 // RDP_NEG_REQ::flags 
				0x08,0x00,                             // RDP_NEG_REQ::length (8 bytes)
				0x00,0x00,0x00,0x00,                    // Requested protocols (PROTOCOL_RDP)
				};
			
			ms.Write(part1, 0, part1.Length);
			ms.Write(b, 0, b.Length);
			ms.Write(part2, 0, part2.Length);
			ms.Seek(0, SeekOrigin.Begin);
			byte[] output = reader.ReadBytes((int) reader.BaseStream.Length);
			return output;
		}


		// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/db6713ee-1c0e-4064-a3b3-0fac30b4037b
		private static byte[] ConnectInitial(string hostname)
		{
			MemoryStream ms = new MemoryStream();
			BinaryReader reader = new BinaryReader(ms);
			byte[] b = Encoding.Unicode.GetBytes(hostname);
			byte[] part1 = new byte[] {
				0x02,0xf0,0x80,             // x.224
				0x7f,0x65,0x82,0x01,0xbe, // change here
				0x04,0x01,0x01,0x04,
				0x01,0x01,0x01,0x01,0xff,
				0x30,0x20,0x02,0x02,0x00,0x22,0x02,0x02,0x00,0x02,0x02,0x02,0x00,0x00,0x02,0x02,0x00,0x01,0x02,0x02,0x00,0x00,0x02,0x02,0x00,0x01,0x02,0x02,0xff,0xff,0x02,0x02,0x00,0x02,0x30,0x20,
				0x02,0x02,0x00,0x01,0x02,0x02,0x00,0x01,0x02,0x02,0x00,0x01,0x02,0x02,0x00,0x01,0x02,0x02,0x00,0x00,0x02,0x02,0x00,0x01,0x02,0x02,0x04,0x20,0x02,0x02,0x00,0x02,0x30,0x20,0x02,0x02,
				0xff,0xff,0x02,0x02,0xfc,0x17,0x02,0x02,0xff,0xff,0x02,0x02,0x00,0x01,0x02,0x02,0x00,0x00,0x02,0x02,0x00,0x01,0x02,0x02,0xff,0xff,0x02,0x02,0x00,0x02,0x04,0x82,0x01,0x4b, // chnage here
				0x00,0x05,0x00,0x14,0x7c,0x00,0x01,0x81,0x42, // change here - ConnectPDU
				0x00,0x08,0x00,0x10,0x00,0x01,0xc0,0x00,0x44,0x75,0x63,0x61,0x81,0x34, // chnage here 
				0x01,0xc0,0xd8,0x00,0x04,0x00,0x08,0x00,0x20,0x03,0x58,0x02,0x01,0xca,0x03,0xaa,0x09,0x04,0x00,0x00,0x28,0x0a,0x00,0x00
			};
			ms.Write(part1, 0, part1.Length);

			ms.Write(b, 0, b.Length);
			for (int i = 0; i < 32 - b.Length; i++)
			{
				ms.WriteByte(0);
			}

			byte[] part2 = new byte[] {
				0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0c,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0xca,0x01,0x00,0x00,0x00,0x00,0x00,0x18,0x00,0x07,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x04,0xc0,0x0c,0x00,0x09,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0xc0,0x0c,0x00,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x03,0xc0,
				0x44,0x00,
				0x04,0x00,0x00,0x00, //channel count
				0x63,0x6c,0x69,0x70,0x72,0x64,0x72,0x00,0xc0,0xa0,0x00,0x00, //cliprdr
				0x4d,0x53,0x5f,0x54,0x31,0x32,0x30,0x00,0x00,0x00,0x00,0x00, //MS_T120
				0x72,0x64,0x70,0x73,0x6e,0x64,0x00,0x00,0xc0,0x00,0x00,0x00, //rdpsnd
				0x73,0x6e,0x64,0x64,0x62,0x67,0x00,0x00,0xc0,0x00,0x00,0x00, //snddbg
				0x72,0x64,0x70,0x64,0x72,0x00,0x00,0x00,0x80,0x80,0x00,0x00, //rdpdr
			};

			ms.Write(part2, 0, part2.Length);
			ms.Seek(0, SeekOrigin.Begin);
			byte[] output = reader.ReadBytes((int) reader.BaseStream.Length);
			return output;
		}

		// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/927de44c-7fe8-4206-a14f-e5517dc24b1c
		private static void ParseServerData(byte[] inbuffer, out byte[] rsmod, out byte[] rsexp, out byte[] server_random,out int bitlen)
		{
			int ptr = 0x45;
			while (ptr < inbuffer.Length)
			{
				int headerType = BitConverter.ToInt16(inbuffer, ptr);
				int headerSize = BitConverter.ToInt16(inbuffer, ptr +2);
				Console.WriteLine("- Header: {0}  Len: {1}", headerType, headerSize);
				if (headerType == 0xC02)
				{
					// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/3e86b68d-3e2e-4433-b486-878875778f4b
					Console.WriteLine("- Security Header");
					int magic = BitConverter.ToInt32(inbuffer, ptr + 68);
					if (magic == 0x31415352)
					{
						bitlen = BitConverter.ToInt32(inbuffer, ptr + 72) - 8;
						server_random = new byte[32];
						Array.Copy(inbuffer, ptr + 20, server_random, 0, 32);
						rsexp = new byte[4];
						Array.Copy(inbuffer, ptr + 84, rsexp, 0, 4);
						rsmod = new byte[bitlen];
						Array.Copy(inbuffer, ptr + 88, rsmod, 0, bitlen);
						return;
					}
				}
				ptr += headerSize;
			}
			throw new NotImplementedException();
		}

		static byte[] reserveBytes(byte[] input)
		{
			byte[] output = new byte[input.Length];
			for (int i = 0; i < input.Length; i++)
			{
				output[input.Length - 1 - i] = input[i];
			}
			return output;
		}

		static byte[] SecuritExchange(byte[] rcran, byte[] rsexp, byte[] rsmod, int bitlen)
		{
			MemoryStream ms = new MemoryStream();
			BinaryReader reader = new BinaryReader(ms);

			RSAParameters rsaparameters = new RSAParameters();
			rsaparameters.Exponent = reserveBytes(rsexp);
			rsaparameters.Modulus = reserveBytes(rsmod);
			RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
			rsa.ImportParameters(rsaparameters);

			byte[] encryptedSecret = reserveBytes(rsa.Encrypt(rcran, false));

			byte[] part2 = new byte[] {
				0x02,0xf0,0x80, //  X.224
				0x64, // sendDataRequest
				0x00,0x08, // intiator userId
				0x03,0xeb, //channelId = 1003
				0x70, // dataPriority
			};
			ms.Write(part2, 0, part2.Length);
			// FIX ME - hardcoded
			ms.WriteByte(0x81);
			ms.WriteByte(0x10);
			//ms.Write(BitConverter.GetBytes((short)(bitlen + 8)), 0, 2);
    
			// 2.2.1.10.1 Security Exchange PDU Data (TS_SECURITY_PACKET)
			// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/ca73831d-3661-4700-9357-8f247640c02e
			byte[] part3 = new byte[] {
				0x01,0x00,
				0x00, 0x00
			}; // SEC_EXCHANGE_PKT
			ms.Write(part3, 0, part3.Length);
			ms.Write(BitConverter.GetBytes((uint)bitlen + 8), 0, 4); // securityPkt length
			ms.Write(encryptedSecret, 0, encryptedSecret.Length); // 64 bytes encrypted client random
			ms.Write(new byte[8] , 0, 8); //8 bytes rear padding (always present)

			ms.Seek(0, SeekOrigin.Begin);
			byte[] output = reader.ReadBytes((int) reader.BaseStream.Length);
			return output;
		}

		// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/705f9542-b0e3-48be-b9a5-cf2ee582607f
		private static void ComputeRC4Keys(byte[] clientrand, byte[] server_random, out byte[] clientEncryptKey, out byte[] clientDecryptKey, out byte[] macKey, out byte[] sessionKey)
		{
			// pre master key
			byte[] preMasterKey = new byte[48];
			Array.Copy(clientrand, preMasterKey, 24);
			Array.Copy(server_random, 0, preMasterKey, 24, 24);

			// master key
			byte[] m1 = SaltedHash(preMasterKey, new byte[] { 0x41 }, clientrand, server_random);
			byte[] m2 = SaltedHash(preMasterKey, new byte[] { 0x42, 0x42 }, clientrand, server_random);
			byte[] m3 = SaltedHash(preMasterKey, new byte[] { 0x43, 0x43, 0x43 }, clientrand, server_random);

			byte[] masterKey = new byte[m1.Length + m2.Length + m3.Length];
			Array.Copy(m1, 0, masterKey, 0, m1.Length);
			Array.Copy(m2, 0, masterKey, m1.Length, m2.Length);
			Array.Copy(m3, 0, masterKey, m1.Length + m2.Length, m3.Length);

			// session key
			byte[] s1 = SaltedHash(masterKey, new byte[] { 0x58 }, clientrand, server_random);
			byte[] s2 = SaltedHash(masterKey, new byte[] { 0x59, 0x59 }, clientrand, server_random);
			byte[] s3 = SaltedHash(masterKey, new byte[] { 0x5A, 0x5A, 0x5A }, clientrand, server_random);

			sessionKey = new byte[s1.Length + s2.Length + s3.Length];
			Array.Copy(s1, 0, sessionKey, 0, s1.Length);
			Array.Copy(s2, 0, sessionKey, s1.Length, s2.Length);
			Array.Copy(s3, 0, sessionKey, s1.Length + s2.Length, s3.Length);

			// keys
			clientDecryptKey = FinalHash(s2, clientrand, server_random);
			clientEncryptKey = FinalHash(s3, clientrand, server_random);
			macKey = s1;
		}

		// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/705f9542-b0e3-48be-b9a5-cf2ee582607f
		static byte[] SaltedHash(byte[] s, byte[] i, byte[] clientRand, byte[] serverRand)
		{
			using (SHA1 sha1 = SHA1.Create())
			using (MD5 md5 = MD5.Create())
			{
				sha1.TransformBlock(i, 0, i.Length, i, 0);
				sha1.TransformBlock(s, 0, s.Length, s, 0);
				sha1.TransformBlock(clientRand, 0, clientRand.Length, clientRand, 0);
				sha1.TransformFinalBlock(serverRand, 0, serverRand.Length);
				md5.TransformBlock(s, 0, s.Length, s, 0);
				md5.TransformFinalBlock(sha1.Hash, 0, sha1.Hash.Length);
				return md5.Hash;
			}
		}

		// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/705f9542-b0e3-48be-b9a5-cf2ee582607f
		static byte[] FinalHash(byte[] k, byte[] clientRand, byte[] serverRand)
		{
			using (MD5 md5 = MD5.Create())
			{
				md5.TransformBlock(k, 0, k.Length, k, 0);
				md5.TransformBlock(clientRand, 0, clientRand.Length, clientRand, 0);
				md5.TransformFinalBlock(serverRand, 0, serverRand.Length);
				return md5.Hash;
			}
		}

		// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/7c61b54e-f6cd-4819-a59a-daf200f6bf94
		static byte[] Hmac(byte[] data, byte[] key)
		{
			byte[] pad1 = new byte[40];
			byte[] pad2 = new byte[48];
			for (int i = 0; i < pad1.Length; i++) pad1[i] = 0x36;
			for (int i = 0; i < pad2.Length; i++) pad2[i] = 0x5c;

			using (SHA1 sha1 = SHA1.Create())
			using (MD5 md5 = MD5.Create())
			{
				sha1.TransformBlock(key, 0, key.Length, key, 0);
				sha1.TransformBlock(pad1, 0, pad1.Length, pad1, 0);
				sha1.TransformBlock(BitConverter.GetBytes(data.Length), 0, 4, BitConverter.GetBytes(data.Length), 0);
				sha1.TransformFinalBlock(data, 0, data.Length);

				md5.TransformBlock(key, 0, key.Length, key, 0);
				md5.TransformBlock(pad2, 0, pad2.Length, pad2, 0);
				md5.TransformFinalBlock(sha1.Hash, 0, sha1.Hash.Length);

				byte[] output = new byte[8];
				Array.Copy(md5.Hash, output, output.Length);
				return output;
			}
		}

		public class RDP_RC4
		{
			byte[] s;
			int i = 0;
			int j = 0;

			public RDP_RC4(byte[] key)
			{
				s = EncryptInitalize(key);
			}

			private static byte[] EncryptInitalize(byte[] key)
			{
				byte[] s = new byte[256];
				for (int i = 0; i < 256; i++)
				{
					s[i] = (byte) i;
				}

				for (int i = 0, j = 0; i < 256; i++)
				{
					j = (j + key[i % key.Length] + s[i]) & 255;

					Swap(s, i, j);
				}

				return s;
			}

			public byte[] Encrypt(byte[] data)
			{
				
				byte[] output = new byte[data.Length];
				for (int l = 0; l < data.Length; l++)
				{
					byte b = data[l];
					i = (i + 1) & 255;
					j = (j + s[i]) & 255;

					Swap(s, i, j);

					output[l] = (byte)(b ^ s[(s[i] + s[j]) & 255]);
				}
				return output;
			}

			private static void Swap(byte[] s, int i, int j)
			{
				byte c = s[i];

				s[i] = s[j];
				s[j] = c;
			}
		}

		static byte[] EncryptPkt(byte[] data, RDP_RC4 Encrypt, byte[] hmacKey, int flags)
		{
			return EncryptPkt(data, Encrypt, hmacKey, flags, 0x3eb);
		}

		static byte[] EncryptPkt(byte[] data, RDP_RC4 Encrypt, byte[] hmacKey)
		{
			return EncryptPkt(data, Encrypt, hmacKey, 8, 0x3eb);
		}

		static byte[] EncryptPkt(byte[] data, RDP_RC4 Encrypt, byte[] hmacKey, int flags, int channelId)
		{
			int udl_with_flag = 0x8000 | (data.Length + 12);

			MemoryStream ms = new MemoryStream();
			BinaryReader reader = new BinaryReader(ms);

			byte[] part1 = new byte[] {
				0x02,0xf0, 0x80, // # X.224
				0x64,  // sendDataRequest
				0x00, 0x08, // intiator userId .. TODO: for a functional client this isn't static
				(byte)(channelId / 0x100), (byte)(channelId % 0x100), // channelId = 1003
				0x70, // dataPriority
			};
			ms.Write(part1, 0, part1.Length);
			ms.WriteByte((byte) (udl_with_flag / 0x100));
			ms.WriteByte((byte)(udl_with_flag % 0x100));
			ms.Write(BitConverter.GetBytes(flags), 0, 2);
			ms.Write(BitConverter.GetBytes(0), 0, 2);

			byte[] hmac = Hmac(data, hmacKey);
			ms.Write(hmac, 0, hmac.Length);

			byte[] rc4 = Encrypt.Encrypt(data);
			ms.Write(rc4, 0, rc4.Length);

			ms.Seek(0, SeekOrigin.Begin);

			byte[] output = reader.ReadBytes((int)reader.BaseStream.Length);
			return output;
		}
	}
}
*/