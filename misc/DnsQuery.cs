//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

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

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 1)]
    internal struct DNS_HEADER
    {
        public ushort Xid;
        public ushort Flags;
        public ushort QuestionCount;
        public ushort AnswerCount;
        public ushort NameServerCount;
        public ushort AdditionalCount;
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
                        switch (partialDnsRecord.type)
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



        enum QueryType
        {
            A = 1,
            MX = 15,
            AAAA = 28,
            DNS_TYPE_ANY = 0x00ff,
            // Add more query types as needed
        }

        enum QueryClass
        {
            IN = 1,
            CH = 3,
            HS = 4
        }


        public static void Revolve(string dnsName)
        {
            const int mdnsPort = 5353;
            using (var udpClient = new UdpClient())
            {

                try
                {
                    udpClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                    udpClient.ExclusiveAddressUse = false;
                    udpClient.Client.Bind(new IPEndPoint(IPAddress.Any, mdnsPort));

                    var multicastAddress = IPAddress.Parse("224.0.0.251");
                    var endPoint = new IPEndPoint(multicastAddress, mdnsPort);

                    // Join the multicast group
                    udpClient.JoinMulticastGroup(multicastAddress);

                    // Set the client to use the multicast address for sending
                    udpClient.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastInterface, IPAddress.HostToNetworkOrder(0));

                    // Send the mDNS query
                    byte[] queryData = CreateDnsQuery(dnsName);
                    udpClient.Send(queryData, queryData.Length, endPoint);

                    while (true)
                    {
                        // Receive the mDNS response
                        byte[] responseData = udpClient.Receive(ref endPoint);

                        Trace.WriteLine("Data received from " + endPoint.Address.ToString());

                        // Parse the mDNS response
                        ParseDnsResponse(responseData);
                    }
                }
                catch (Exception)
                {
                    throw;
                }
            }
        }

        // Create a DNS query for the specified domain name
        private static byte[] CreateDnsQuery(string domainName)
        {
            var querySize = 0;
            NativeMethods.DnsWriteQuestionToBuffer(null, ref querySize, domainName, (int)QueryType.DNS_TYPE_ANY, 0, false);
            if (querySize == 0)
            {
                throw new Win32Exception("Unable to get size of DnsWriteQuestionToBuffer");
            }


            byte[] query = new byte[querySize]; // Adjust the buffer size as needed
            if (!NativeMethods.DnsWriteQuestionToBuffer(query, ref querySize, domainName, (int)QueryType.DNS_TYPE_ANY, 0, false))
            {
                throw new Win32Exception("Unable to get size of DnsWriteQuestionToBuffer 2");
            }

            return query;
        }

        static ushort reverse(ushort value)
        {
            return (ushort)((value << 8) | (value >> 8));
        }

        // Parse the DNS response using DnsExtractRecordsFromMessage / not really working
        private static void ParseDnsResponse(byte[] response)
        {
            IntPtr dnsResultList = IntPtr.Zero;
            try
            {
                if (response.Length < Marshal.SizeOf(typeof(DNS_HEADER)))
                {
                    return;
                }

                IntPtr ptr = IntPtr.Zero;
                try
                {
                    ptr = Marshal.AllocHGlobal(response.Length);
                    Marshal.Copy(response, 0, ptr, response.Length);
                    var header = (DNS_HEADER)Marshal.PtrToStructure(ptr, typeof(DNS_HEADER));
                    Marshal.FreeHGlobal(ptr);
                    ptr = IntPtr.Zero;

                    header.Xid = reverse(header.Xid);
                    header.QuestionCount = reverse(header.QuestionCount);
                    header.AnswerCount = reverse(header.AnswerCount);
                    header.NameServerCount = reverse(header.NameServerCount);
                    header.AdditionalCount = reverse(header.AdditionalCount);

                    ptr = Marshal.AllocHGlobal(response.Length);
                    Marshal.StructureToPtr(header, ptr, true);
                    Marshal.Copy(ptr, response, 0, Marshal.SizeOf(typeof(DNS_HEADER)));
                }
                finally
                {
                    Marshal.FreeHGlobal(ptr);
                }



                var res = NativeMethods.DnsExtractRecordsFromMessage(response, response.Length, out dnsResultList);
                if (!res)
                {
                    var error = Marshal.GetLastWin32Error();
                }
                var intPtr = dnsResultList;
                while (intPtr != IntPtr.Zero)
                {
                    PartialDnsRecord partialDnsRecord = new PartialDnsRecord();
                    Marshal.PtrToStructure(intPtr, (object)partialDnsRecord);
                    switch (partialDnsRecord.type)
                    {
                        default:
                            Trace.WriteLine("DNS: type: " + partialDnsRecord.type + " value: " + partialDnsRecord.name);
                            break;
                    }
                    intPtr = partialDnsRecord.next;
                }
            }
            finally
            {
                if (dnsResultList != IntPtr.Zero)
                {
                    NativeMethods.DnsRecordListFree(dnsResultList, dnsFreeType: true);
                }
            }
        }

    }
}


