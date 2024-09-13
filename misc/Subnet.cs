using System;
using System.Net;

namespace PingCastle.misc
{
    public class Subnet
    {
        private int _mask;
        private byte[] _startAddress;

        public IPAddress StartAddress { get; private set; }
        public IPAddress EndAddress { get; private set; }

        public Subnet(IPAddress startAddress, int mask)
        {
            _mask = mask;
            _startAddress = startAddress.GetAddressBytes();
            var endAddress = startAddress.GetAddressBytes();
            ApplyBitMask(_startAddress);
            StartAddress = new IPAddress(_startAddress);
            ApplyBitMask(endAddress, true);
            EndAddress = new IPAddress(endAddress);
        }

        public Subnet(IPAddress startAddress, IPAddress endAddress)
        {
            StartAddress = startAddress;
            _startAddress = startAddress.GetAddressBytes();
            EndAddress = endAddress;
            _mask = -1;
        }

        public override string ToString()
        {
            if (_mask >= 0)
                return StartAddress.ToString() + "/" + _mask;
            return StartAddress.ToString() + "-" + EndAddress.ToString();
        }

        private void ApplyBitMask(byte[] address, bool setBits = false)
        {
            int remainingMask = _mask;
            for (int i = 0; i < address.Length; i++)
            {
                if (remainingMask >= 8)
                {
                    remainingMask -= 8;
                    continue;
                }
                if (remainingMask == 0)
                {
                    if (setBits)
                        address[i] = 0xFF;
                    else
                        address[i] = 0;
                    continue;
                }
                byte mask = (byte)(0xFF00 >> remainingMask);
                if (setBits)
                    address[i] = (byte)((address[i] & mask) + ~mask);
                else
                    address[i] = (byte)(address[i] & mask);
                remainingMask = 0;
            }
        }

        public bool MatchIp(IPAddress ipaddress)
        {
            byte[] ipAddressBytes = ipaddress.GetAddressBytes();
            if (ipAddressBytes.Length != _startAddress.Length)
                return false;
            if (_mask >= 0)
            {
                ApplyBitMask(ipAddressBytes);
                for (int i = 0; i < _startAddress.Length; i++)
                {
                    if (ipAddressBytes[i] != _startAddress[i]) return false;
                }
                return true;
            }
            return CompareIPAddresses(StartAddress, ipaddress) <= 0 && CompareIPAddresses(ipaddress, EndAddress) <= 0;
        }

        static int CompareIPAddresses(IPAddress ip1, IPAddress ip2)
        {
            byte[] ip1Bytes = ip1.GetAddressBytes();
            byte[] ip2Bytes = ip2.GetAddressBytes();

            if (ip1Bytes.Length != ip2Bytes.Length)
            {
                throw new ArgumentException("IP addresses must have the same length.");
            }

            for (int i = 0; i < ip1Bytes.Length; i++)
            {
                if (ip1Bytes[i] < ip2Bytes[i]) return -1;
                if (ip1Bytes[i] > ip2Bytes[i]) return 1;
            }

            return 0;
        }

        public static Subnet Parse(string subnet)
        {
            IPAddress lowIP, highIP;
            int bits;
            var parts = subnet.Split('/');
            if (parts.Length == 2 && IPAddress.TryParse(parts[0], out lowIP) && int.TryParse(parts[1], out bits))
            {
                return new Subnet(lowIP, bits);
            }
            parts = subnet.Split('-');
            if (parts.Length == 2 && IPAddress.TryParse(parts[0], out lowIP) && IPAddress.TryParse(parts[1], out highIP) && lowIP.AddressFamily == highIP.AddressFamily)
            {
                return new Subnet(lowIP, highIP);
            }
            throw new ArgumentException("invalid subnet: " + subnet);
        }
    }
}
