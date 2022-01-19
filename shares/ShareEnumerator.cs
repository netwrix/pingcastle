//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Permissions;
using System.Security.Principal;

namespace PingCastle.shares
{
    public class ShareEnumerator
    {

        private static bool IsEveryoneHere(FileSystemSecurity fss)
        {
            foreach (FileSystemAccessRule accessrule in fss.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                // ignore audit / denied ace
                if (accessrule.AccessControlType != AccessControlType.Allow)
                    continue;
                if (((SecurityIdentifier)accessrule.IdentityReference).IsWellKnown(WellKnownSidType.WorldSid)
                    || ((SecurityIdentifier)accessrule.IdentityReference).IsWellKnown(WellKnownSidType.AuthenticatedUserSid)
                    || ((SecurityIdentifier)accessrule.IdentityReference).IsWellKnown(WellKnownSidType.BuiltinUsersSid)
                    || ((SecurityIdentifier)accessrule.IdentityReference).IsWellKnown(WellKnownSidType.AccountComputersSid)
                    || ((SecurityIdentifier)accessrule.IdentityReference).IsWellKnown(WellKnownSidType.AccountDomainUsersSid)
                    || ((SecurityIdentifier)accessrule.IdentityReference).IsWellKnown(WellKnownSidType.AnonymousSid)
                    )
                {
                    return true;
                }
            }
            return false;
        }

        public static bool IsEveryoneAllowed(string server, string share)
        {
            string path = "\\\\" + server + "\\" + share + "\\";
            try
            {
                DirectoryInfo di = new DirectoryInfo(path);
                // special case for the Users default folder
                if (share.Equals("Users", StringComparison.InvariantCultureIgnoreCase))
                {
                    foreach (DirectoryInfo di2 in di.GetDirectories())
                    {
                        if (di2.Name.Equals("Default", StringComparison.InvariantCultureIgnoreCase))
                            continue;
                        FileSystemSecurity fss = di2.GetAccessControl(AccessControlSections.Access);
                        if (IsEveryoneHere(fss))
                        {
                            return true;
                        }
                    }
                }
                else
                {
                    FileSystemSecurity fss = di.GetAccessControl(AccessControlSections.Access);
                    if (IsEveryoneHere(fss))
                    {
                        return true;
                    }
                }
            }
            catch (Exception ex)
            {
                Trace.WriteLine(path + " " + ex.Message);
            }
            return false;
        }

        public static bool IsCurrentUserAllowed(string server, string share)
        {
            string path = "\\\\" + server + "\\" + share + "\\";
            try
            {
                DirectoryInfo di = new DirectoryInfo(path);
                // special case for the Users default folder
                if (share.Equals("Users", StringComparison.InvariantCultureIgnoreCase))
                {
                    foreach (DirectoryInfo di2 in di.GetDirectories())
                    {
                        if (di2.Name.Equals("Default", StringComparison.InvariantCultureIgnoreCase))
                            continue;

                        try
                        {
                            var files = System.IO.Directory.GetFiles(path);
                            return true;
                        }
                        catch
                        {
                            continue;
                        }
                    }
                    return false;
                }
                else
                {
                    try
                    {
                        var files = System.IO.Directory.GetFiles(path);
                        return true;
                    }
                    catch
                    {
                        return false;
                    }
                }
            }
            catch (Exception ex)
            {
                Trace.WriteLine(path + " " + ex.Message);
            }
            return false;
        }

        public static bool IsSensitiveFilePresent(string server, string share)
        {
            string path = "\\\\" + server + "\\" + share + "\\";
            try
            {
                DirectoryInfo di = new DirectoryInfo(path);
                foreach (FileInfo fi in di.GetFiles("*.*", SearchOption.AllDirectories))
                {
                    // filezilla configuration
                    if (fi.Name.Equals("sitemanager.xml", StringComparison.InvariantCultureIgnoreCase))
                    {
                        return true;
                    }
                    // backup files
                    if (fi.Extension.Equals("bak", StringComparison.InvariantCultureIgnoreCase))
                    {
                        return true;
                    }
                }
            }
            catch (Exception ex)
            {
                Trace.WriteLine(path + " " + ex.Message);
            }
            return false;
        }

        [SecurityPermission(SecurityAction.Demand)]
        public static List<string> EnumShare(string server)
        {
            List<string> output = new List<string>();
            int entriesread = 0;
            int totalentries = 0;
            int resume_handle = 0;
            int nStructSize = Marshal.SizeOf(typeof(NativeMethods.SHARE_INFO_1));
            IntPtr bufPtr = IntPtr.Zero;
            int ret = NativeMethods.NetShareEnum(server, 1, ref bufPtr, 0xFFFFFFFF, ref entriesread, ref totalentries, ref resume_handle);
            if (ret == 0)
            {
                IntPtr currentPtr = bufPtr;
                for (int i = 0; i < entriesread; i++)
                {
                    NativeMethods.SHARE_INFO_1 shi1 = (NativeMethods.SHARE_INFO_1)Marshal.PtrToStructure(currentPtr, typeof(NativeMethods.SHARE_INFO_1));
                    if ((shi1.shi1_type & 0xF) == 0)
                    {
                        output.Add(shi1.shi1_netname);
                    }
                    currentPtr = new IntPtr(currentPtr.ToInt64() + nStructSize);
                }
                NativeMethods.NetApiBufferFree(bufPtr);
            }
            return output;
        }
    }
}
