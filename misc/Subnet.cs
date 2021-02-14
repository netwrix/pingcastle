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

        public override string ToString()
        {
            return StartAddress.ToString() + "/" + _mask;
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
            ApplyBitMask(ipAddressBytes);
            for (int i = 0; i < _startAddress.Length; i++)
            {
                if (ipAddressBytes[i] != _startAddress[i]) return false;
            }
            return true;
        }

        public static Subnet Parse(string subnet)
        {
            IPAddress lowIP;
            int bits;
            var parts = subnet.Split('/');
            if (parts.Length == 2 && IPAddress.TryParse(parts[0], out lowIP) && int.TryParse(parts[1], out bits))
            {
                return new Subnet(lowIP, bits);
            }
            throw new ArgumentException("invalid subnet: " + subnet);
        }
    }
}
