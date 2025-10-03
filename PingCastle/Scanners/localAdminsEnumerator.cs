//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using System.Security.Principal;

namespace PingCastle.Scanners
{

    public class localAdminsEnumerator
    {

        const int SAM_SERVER_CONNECT = 0x00000001;
        const int SAM_SERVER_LOOKUP_DOMAIN = 0x00000020;
        const int DOMAIN_LIST_ACCOUNTS = 0x00000100;
        const int DOMAIN_LOOKUP = 0x00000200;
        const int ALIAS_LIST_MEMBERS = 0x00000004;
        const int DOMAIN_ALIAS_RID_ADMINS = 0x00000220;
        const int timeout = 2;

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2202:Ne pas supprimer d'objets plusieurs fois")]
        public static bool IsServerAvailable(string ServerName)
        {
            var result = false;
            using (var client = new TcpClient())
            {
                try
                {
                    client.ReceiveTimeout = timeout * 1000;
                    client.SendTimeout = timeout * 1000;
                    var asyncResult = client.BeginConnect(ServerName, 445, null, null);
                    var waitHandle = asyncResult.AsyncWaitHandle;
                    try
                    {
                        if (!asyncResult.AsyncWaitHandle.WaitOne(TimeSpan.FromSeconds(timeout), false))
                        {
                            // wait handle didn't came back in time
                            client.Close();
                        }
                        else
                        {
                            // The result was positiv
                            result = client.Connected;
                        }
                        // ensure the ending-call
                        client.EndConnect(asyncResult);
                    }
                    finally
                    {
                        // Ensure to close the wait handle.
                        waitHandle.Close();
                    }
                }
                catch
                {
                }
            }
            return result;
        }

        [SecurityPermission(SecurityAction.Demand)]
        public static List<SecurityIdentifier> Export(string ServerName)
        {
            int status;
            NativeMethods.UNICODE_STRING serverName = new NativeMethods.UNICODE_STRING();
            serverName.Initialize(ServerName);
            List<SecurityIdentifier> output = new List<SecurityIdentifier>();

            IntPtr hServerHandle, hBuiltinHandle, hAliasHandle;
            IntPtr membersSid;
            int memberRetourned;

            status = NativeMethods.SamConnect(ref serverName, out hServerHandle, SAM_SERVER_CONNECT | SAM_SERVER_LOOKUP_DOMAIN, 0);
            serverName.Dispose();
            if (status != 0)
                throw new Win32Exception(NativeMethods.LsaNtStatusToWinError(status));
            try
            {
                byte[] builtin = new byte[SecurityIdentifier.MaxBinaryLength];
                new SecurityIdentifier("S-1-5-32").GetBinaryForm(builtin, 0);
                status = NativeMethods.SamOpenDomain(hServerHandle, DOMAIN_LIST_ACCOUNTS | DOMAIN_LOOKUP, builtin, out hBuiltinHandle);
                if (status != 0)
                    throw new Win32Exception(NativeMethods.LsaNtStatusToWinError(status));
                try
                {
                    status = NativeMethods.SamOpenAlias(hBuiltinHandle, ALIAS_LIST_MEMBERS, DOMAIN_ALIAS_RID_ADMINS, out hAliasHandle);
                    if (status != 0)
                        throw new Win32Exception(NativeMethods.LsaNtStatusToWinError(status));
                    try
                    {
                        status = NativeMethods.SamGetMembersInAlias(hAliasHandle, out membersSid, out memberRetourned);
                        if (status != 0)
                            throw new Win32Exception(NativeMethods.LsaNtStatusToWinError(status));
                        for (int i = 0; i < memberRetourned; i++)
                        {
                            SecurityIdentifier sid = new SecurityIdentifier(Marshal.ReadIntPtr(membersSid, Marshal.SizeOf(typeof(IntPtr)) * i));
                            output.Add(sid);
                        }
                        NativeMethods.SamFreeMemory(membersSid);
                    }
                    finally
                    {
                        NativeMethods.SamCloseHandle(hAliasHandle);
                    }
                }
                finally
                {
                    NativeMethods.SamCloseHandle(hBuiltinHandle);
                }
            }
            finally
            {
                NativeMethods.SamCloseHandle(hServerHandle);
            }
            return output;
        }
    }
}