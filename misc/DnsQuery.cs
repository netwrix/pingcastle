//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;

namespace PingCastle.misc
{
    public class DnsRecord2
    { 
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal sealed class PartialDnsRecord
    {
        public IntPtr next;

        public string name;

        public short type;

        public short dataLength;

        public int flags;

        public int ttl;

        public int reserved;

        public IntPtr data;
    }

    public class DnsQuery
    {
        public static bool IsZoneTransfertActive(string domainName)
        {
            IntPtr dnsResultList = IntPtr.Zero;

            const int DNS_TYPE_AXFR = 0x00fc;
            const int DNS_QUERY_BYPASS_CACHE = 0x00000008;
            const int DNS_QUERY_STANDARD = 0x00000000;
            const int DNS_QUERY_USE_TCP_ONLY = 0x00000002;
            int num = NativeMethods.DnsQuery(domainName, DNS_TYPE_AXFR, DNS_QUERY_BYPASS_CACHE | DNS_QUERY_STANDARD | DNS_QUERY_USE_TCP_ONLY, IntPtr.Zero, out dnsResultList, IntPtr.Zero);
            if (num == 0)
            {
                try
                {
                    IntPtr intPtr = dnsResultList;
                    while (intPtr != IntPtr.Zero)
                    {
                        PartialDnsRecord partialDnsRecord = new PartialDnsRecord();
                        Marshal.PtrToStructure(intPtr, (object)partialDnsRecord);
                        switch(partialDnsRecord.type)
                        {
                            default:
                                Trace.WriteLine("DNS: type: " + partialDnsRecord.type + " value: " + partialDnsRecord.name);
                                break;
                        }
                        intPtr = partialDnsRecord.next;
                    }
                    return true;
                }
                finally
                {
                    if (dnsResultList != IntPtr.Zero)
                    {
                        NativeMethods.DnsRecordListFree(dnsResultList, dnsFreeType: true);
                    }
                }
            }
            if (num != 0)
            {
                Trace.WriteLine("DnsQuery for zone transfert returned " + num);
            }
            return false;
        }
    }
}
