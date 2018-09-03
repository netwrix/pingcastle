//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace PingCastle.Healthcheck.Rules
{
	[HeatlcheckRuleModel("S-DC-SubnetMissing", HealthcheckRiskRuleCategory.StaleObjects, HealthcheckRiskModelCategory.NetworkTopography)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnPresence, 5)]
    public class HeatlcheckRuleStaledDCSubnetMissing : HeatlcheckRuleBase
    {
		private class Subnet
		{
			private int _mask;
			private byte[] _startAddress;

			public Subnet(IPAddress startAddress, int mask)
			{
				_mask = mask;
				_startAddress = startAddress.GetAddressBytes();
				ApplyBitMask(_startAddress);
			}

			private void ApplyBitMask(byte[] address)
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
						address[i] = 0;
						continue;
					}
					address[i] = (byte) (address[i] & (0xFF00 >> remainingMask));
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
		}

		protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
			var subnets = new List<Subnet>();
			foreach (var site in healthcheckData.Sites)
			{
				foreach (var subnet in site.Networks)
				{
					IPAddress lowIP;
					int bits;
					var parts = subnet.Split('/');
					if (parts.Length == 2 && IPAddress.TryParse(parts[0], out lowIP) && int.TryParse(parts[1], out bits))
					{
						subnets.Add(new Subnet(lowIP, bits));
					}
				}
			}
			foreach (var dc in healthcheckData.DomainControllers)
			{
				if (dc.IP != null)
				{
					foreach (string ip in dc.IP)
					{
						var ipaddress = IPAddress.Parse(ip);
						bool found = false;
						foreach (var subnet in subnets)
						{
							if (subnet.MatchIp(ipaddress))
							{
								found = true;
								break;
							}
						}
						if (!found)
						{
							AddRawDetail(dc.DCName, ip);
						}
					}
				}
			}
			return null;
        }
    }
}
