//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.NullSession;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using System.Security.Principal;
using System.Text;

namespace PingCastle.Scanners
{
	public class AccountEnumeratorViaTrust
    {
        public delegate void Enumerate(SecurityIdentifier sid, NTAccount account);

        public Enumerate EnumerateCallback { get; set; }
        public string Server { get; set; }

		public AccountEnumeratorViaTrust(string server, Enumerate enumerateCallback = null)
        {
            Server = server;
            EnumerateCallback = enumerateCallback;
        }

		[SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        public void EnumerateAccount(SecurityIdentifier DomainSid, int MaximumNumber = int.MaxValue)
        {
			NativeMethods.UNICODE_STRING us = new NativeMethods.UNICODE_STRING();
			NativeMethods.LSA_OBJECT_ATTRIBUTES loa = new NativeMethods.LSA_OBJECT_ATTRIBUTES();
			us.Initialize(Server);
			IntPtr PolicyHandle = IntPtr.Zero;
			int ret = NativeMethods.LsaOpenPolicy(ref us, ref loa, 0x00000800, out PolicyHandle);
			if (ret != 0)
			{
				Trace.WriteLine("LsaOpenPolicy 0x" + ret.ToString("x"));
			}
			try
			{
				uint currentRid = 500;
                int iteration = 0;
				int returnCode = 0;
				int UserEnumerated = 0;
                // allows 10*1000 sid non resolved
                int retrycount = 0;
				while ((returnCode == 0 || returnCode == 0x00000107 || (retrycount < 10 && returnCode == -1073741709)) && UserEnumerated < MaximumNumber)
				{
					Trace.WriteLine("LsaLookupSids iteration " + iteration++);
					List<GCHandle> HandleToFree = new List<GCHandle>();
					IntPtr Names = IntPtr.Zero, ReferencedDomains = IntPtr.Zero;
					try
					{
						SecurityIdentifier[] SidEnumBuffer = new SecurityIdentifier[1000];
						IntPtr[] SidHandles = new IntPtr[SidEnumBuffer.Length];
						for (int i = 0; i < SidEnumBuffer.Length; i++)
						{
							SidEnumBuffer[i] = NullSessionTester.BuildSIDFromDomainSidAndRid(DomainSid, currentRid++);
							byte[] sid = new byte[SidEnumBuffer[i].BinaryLength];
							SidEnumBuffer[i].GetBinaryForm(sid, 0);
							GCHandle handlesid = GCHandle.Alloc(sid, GCHandleType.Pinned);
							HandleToFree.Add(handlesid);
							SidHandles[i] = handlesid.AddrOfPinnedObject();
						}
						GCHandle sidHandle = GCHandle.Alloc(SidHandles, GCHandleType.Pinned);
						HandleToFree.Add(sidHandle);

						returnCode = NativeMethods.LsaLookupSids(PolicyHandle, SidEnumBuffer.Length, sidHandle.AddrOfPinnedObject(), out ReferencedDomains, out Names);
						if (returnCode == 0 || returnCode == 0x00000107)
						{
							retrycount = 0;
							NativeMethods.LSA_TRANSLATED_NAME[] lsaNames = new NativeMethods.LSA_TRANSLATED_NAME[SidEnumBuffer.Length];
							NativeMethods.LSA_REFERENCED_DOMAIN_LIST domainList = (NativeMethods.LSA_REFERENCED_DOMAIN_LIST)Marshal.PtrToStructure(ReferencedDomains, typeof(NativeMethods.LSA_REFERENCED_DOMAIN_LIST));
							for (int i = 0; i < SidEnumBuffer.Length; i++)
							{
								lsaNames[i] = (NativeMethods.LSA_TRANSLATED_NAME)Marshal.PtrToStructure(
									new IntPtr(Names.ToInt64() + i * Marshal.SizeOf(typeof(NativeMethods.LSA_TRANSLATED_NAME)))
									, typeof(NativeMethods.LSA_TRANSLATED_NAME));
								if (lsaNames[i].Use > 0 && lsaNames[i].Use != NativeMethods.SID_NAME_USE.SidTypeUnknown)
								{
									string account = lsaNames[i].Name.ToString();
									if (!String.IsNullOrEmpty(account))
									{
										NativeMethods.LSA_TRUST_INFORMATION trustInfo = (NativeMethods.LSA_TRUST_INFORMATION)Marshal.PtrToStructure
											(new IntPtr(domainList.Domains.ToInt64() + lsaNames[i].DomainIndex * Marshal.SizeOf(typeof(NativeMethods.LSA_TRUST_INFORMATION))), typeof(NativeMethods.LSA_TRUST_INFORMATION));
										EnumerateCallback(SidEnumBuffer[i], new NTAccount(trustInfo.Name.ToString(), account));
									}
								}
							}
						}
						else
						{
							retrycount++;
							Trace.WriteLine("LsaLookupSids " + returnCode);
						}
					}
					finally
					{
						if (ReferencedDomains != IntPtr.Zero)
							NativeMethods.LsaFreeMemory(ReferencedDomains);
						if (Names != IntPtr.Zero)
							NativeMethods.LsaFreeMemory(Names);
						foreach(GCHandle handle in HandleToFree)
							handle.Free();
					}
				}
			}
			finally
			{
				NativeMethods.LsaClose(PolicyHandle);
			}
        }
	}
}
