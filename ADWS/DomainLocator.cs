//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using System.Text;

namespace PingCastle.ADWS
{
    public class DomainLocator
    {

        string Server;
        public DomainLocator(string server)
        {
            Server = server;
        }

        public bool LocateDomainFromNetbios(string netbios, out string domain, out string forest)
        {
            // DS_IS_FLAT_NAME = 0x00010000,
            // DS_RETURN_DNS_NAME = 0x40000000,
            // DS_ONLY_LDAP_NEEDED = 0x00008000,
            return LocateSomething(netbios, out domain, out forest, 0x40018000);
        }

        public bool LocateNetbiosFromFQDN(string fqdn, out string netbios, out string forest)
        {
            // DS_IS_DNS_NAME = 0x00020000,
            // DS_RETURN_FLAT_NAME = 0x80000000
            // DS_ONLY_LDAP_NEEDED = 0x00008000,
            return LocateSomething(fqdn, out netbios, out forest, 0x80028000);
        }

        [SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        bool LocateSomething(string intput, out string domain, out string forest, uint flag)
        {
            IntPtr DomainInfoResolution;
            domain = null;
            forest = null;
            Trace.WriteLine("Trying to solve " + intput + "(" + DateTime.Now.ToString("u") + ")");
            
            int ret = NativeMethods.DsGetDcName(Server, intput, IntPtr.Zero, null, flag, out DomainInfoResolution);
            if (ret == 0)
            {
                Trace.WriteLine("DsGetDcName for " + intput + " succeeded (" + DateTime.Now.ToString("u") + ")");
                NativeMethods.DOMAIN_CONTROLLER_INFO di = (NativeMethods.DOMAIN_CONTROLLER_INFO)Marshal.PtrToStructure(DomainInfoResolution, typeof(NativeMethods.DOMAIN_CONTROLLER_INFO));
                domain = di.DomainName.ToLowerInvariant();
                forest = di.DnsForestName.ToLowerInvariant();
                NativeMethods.NetApiBufferFree(DomainInfoResolution);
                return true;
            }
            else if (ret == 0x0000054B)
            {
                Trace.WriteLine("DsGetDcName for " + intput + " domain not found (" + DateTime.Now.ToString("u") + ")");
            }
            else
            {
                Trace.WriteLine("DsGetDcName for " + intput + " failed 0x" + ret.ToString("x") + " (" + DateTime.Now.ToString("u") + ")");
            }
            return false;
        }


        //// use the locator service of a DC via DsGetDcName
        //// do a parallele resolution because it can takes time
        //private int ResolveNetbiosNameToFQDN(ref string lastWorkingDC, ADDomainInfo domainInfo, string NetbiosName, out IntPtr DomainInfoResolution)
        //{
        //    int ret = 0x0000054B;
        //    DomainInfoResolution = IntPtr.Zero;
        //    BlockingQueue<string> queue = new BlockingQueue<string>(50);
        //    int numberOfThread = 20;
        //    Thread[] threads = new Thread[numberOfThread];
        //    string workingDC = lastWorkingDC;
        //    IntPtr workingoutput = IntPtr.Zero;
        //    bool stop = false;
        //    ThreadStart threadFunction = () =>
        //    {
        //        for (; ; )
        //        {
        //            string dc = null;
        //            IntPtr output;
        //            int threadret = 0;
        //            if (!queue.Dequeue(out dc)) break;
        //            if (!stop)
        //            {
        //                Trace.WriteLine("Trying DC " + dc + "." + domainInfo.DomainName);
        //                threadret = NativeMethods.DsGetDcName(dc + "." + domainInfo.DomainName, NetbiosName, IntPtr.Zero, null, 0x00010000 + 0x40000000 + 0x00008000, out output);
        //                if (threadret == 0)
        //                {
        //                    Trace.WriteLine("DsGetDcName for " + NetbiosName + "for DC " + dc + "." + domainInfo.DomainName + " worked");
        //                    lock (queue)
        //                    {
        //                        workingDC = dc + "." + domainInfo.DomainName;
        //                        workingoutput = output;
        //                        ret = threadret;
        //                        stop = true;
        //                    }
        //                }
        //                else
        //                {
        //                    Trace.WriteLine("DsGetDcName for " + NetbiosName + "for DC " + dc + "." + domainInfo.DomainName + " returned 0x" + ret.ToString("x"));
        //                }
        //            }
        //        }
        //    };
        //    try
        //    {
        //        // Consumers
        //        for (int i = 0; i < numberOfThread; i++)
        //        {
        //            threads[i] = new Thread(threadFunction);
        //            threads[i].Start();
        //        }

        //        foreach (string dc in healthcheckData.DomainControllers)
        //        {
        //            if ((dc + "." + domainInfo.DomainName).Equals(domainInfo.DnsHostName, StringComparison.InvariantCultureIgnoreCase))
        //                continue;
        //            if ((dc + "." + domainInfo.DomainName).Equals(lastWorkingDC, StringComparison.InvariantCultureIgnoreCase))
        //                continue;
        //            queue.Enqueue(dc);
        //        }
        //    }
        //    finally
        //    {
        //        queue.Quit();
        //        DomainInfoResolution = workingoutput;
        //        lastWorkingDC = workingDC;
        //        for (int i = 0; i < numberOfThread; i++)
        //        {
        //            if (threads[i] != null)
        //                if (threads[i].ThreadState == System.Threading.ThreadState.Running)
        //                    threads[i].Abort();
        //        }
        //    }
        //    return ret;
        //}

    }
}
