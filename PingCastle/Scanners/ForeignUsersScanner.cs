//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.RPC;
using PingCastle.UserInterface;
using PingCastleCommon;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using System.Security.Principal;

namespace PingCastle.Scanners
{
    public class ForeignUsersScanner : IScanner
    {

        public string Name { get { return "foreignusers"; } }
        public string Description { get { return "Use trusts to enumerate users located in domain denied such as bastion or domains too far away."; } }

        public static string EnumInboundSid { get; set; }

        RuntimeSettings Settings;

        private readonly IUserInterface _ui = UserInterfaceFactory.GetUserInterface();

        public void Initialize(RuntimeSettings settings)
        {
            Settings = settings;
        }

        public DisplayState QueryForAdditionalParameterInInteractiveMode()
        {
            var state = Settings.EnsureDataCompleted("Server");
            if (state != DisplayState.Run)
                return state;

            IUserInterface userInterface = UserInterfaceFactory.GetUserInterface();
            do
            {
                userInterface.Title = "Select the targeted domain";
                userInterface.Information = @"This scanner enumerate all the users of a trusted domain. Typically it can be a domain trusted by a domain you trust or an inbound trust such as a bastion.
The server for the pivot will be asked next.

Please enter the foreign domain targeted using its FQDN or sids
Example of SID: S-1-5-21-4005144719-3948538632-2546531719
Example of FQDN: bastion.local";
                EnumInboundSid = userInterface.AskForString();

                // error message in case the query is not complete
                userInterface.Notice = "The SID of FQDN cannot be empty";
            } while (String.IsNullOrEmpty(EnumInboundSid));
            userInterface.Notice = null;

            return DisplayState.Run;
        }

        public void Export(string filename)
        {
            StreamWriter sw = null;
            DisplayAdvancement("Getting the domain sid");
            SecurityIdentifier EnumInboundTrustSid = null;
            if (EnumInboundSid.StartsWith("S-1-5-", StringComparison.InvariantCultureIgnoreCase))
            {
                try
                {
                    EnumInboundTrustSid = new SecurityIdentifier(EnumInboundSid).AccountDomainSid;
                }
                catch (Exception ex)
                {
                    throw new PingCastleException("The SID couldn't be parsed (error:" + ex.Message + ")");
                }
            }
            else
            {
                EnumInboundTrustSid = NativeMethods.GetSidFromDomainNameWithWindowsAPI(Settings.Server, EnumInboundSid);
            }
            if (EnumInboundTrustSid == null)
            {
                throw new PingCastleException("The domain " + EnumInboundSid + " couldn't be translated to a sid");
            }
            filename = AddSuffix(filename, "_" + EnumInboundSid);

            filename = FilesValidator.CheckPathTraversalAbsolute(filename);

            using (sw = File.CreateText(filename))
            {
                sw.WriteLine("SID\tAccount");
                DisplayAdvancement("Using the domain SID " + EnumInboundTrustSid.Value);
                EnumerateAccount(EnumInboundTrustSid, int.MaxValue, sw);
            }
        }

        string AddSuffix(string filename, string suffix)
        {
            string fDir = Path.GetDirectoryName(filename);
            string fName = Path.GetFileNameWithoutExtension(filename);
            string fExt = Path.GetExtension(filename);
            return Path.Combine(fDir, String.Concat(fName, suffix, fExt));
        }

        private void DisplayAdvancement(string data)
        {
            string value = "[" + DateTime.Now.ToLongTimeString() + "] " + data;
            _ui.DisplayError(value);
            Trace.WriteLine(value);
        }

        private void DisplayError(string data)
        {
            string value = "[" + DateTime.Now.ToLongTimeString() + "] " + data;
            _ui.DisplayError(value);
            Trace.WriteLine(value);
        }

        [SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        public void EnumerateAccount(SecurityIdentifier DomainSid, int MaximumNumber, StreamWriter sw)
        {
            NativeMethods.UNICODE_STRING us = new NativeMethods.UNICODE_STRING();
            NativeMethods.LSA_OBJECT_ATTRIBUTES loa = new NativeMethods.LSA_OBJECT_ATTRIBUTES();
            us.Initialize(Settings.Server);
            IntPtr PolicyHandle = IntPtr.Zero;
            uint ret = NativeMethods.LsaOpenPolicy(ref us, ref loa, 0x00000800, out PolicyHandle);
            us.Dispose();
            if (ret != 0)
            {
                DisplayError("Error when connecting to the remote domain LsaOpenPolicy 0x" + ret.ToString("x"));
            }
            try
            {
                DisplayAdvancement("Connection established");
                uint currentRid = 500;
                int iteration = 0;
                uint returnCode = 0;
                int UserEnumerated = 0;
                // allows 10*1000 sid non resolved
                int retrycount = 0;
                while ((returnCode == 0 || returnCode == 0x00000107 || (retrycount < 10 && returnCode == 0xC0000073)) && UserEnumerated < MaximumNumber)
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
                                        sw.WriteLine(SidEnumBuffer[i] + "\t" + new NTAccount(trustInfo.Name.ToString(), account).Value);
                                        UserEnumerated++;
                                        if (UserEnumerated % 100 == 0)
                                        {
                                            DisplayAdvancement("Account enumerated: " + UserEnumerated);
                                        }
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
                        foreach (GCHandle handle in HandleToFree)
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
