//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;

namespace PingCastle.Healthcheck
{
    public class TrustAnalyzer
    {

        static bool IsFlagSet(int value, int flag)
        {
            return (value & flag) != 0;
        }

        static public string GetSIDFiltering(HealthCheckTrustData trust)
        {
            return GetSIDFiltering(trust.TrustDirection, trust.TrustAttributes);
        }

        static public string GetSIDFiltering(int TrustDirection, int TrustAttributes)
        {
            // inbound or intra forest
            if (TrustDirection == 0 || TrustDirection == 1 || IsFlagSet(TrustAttributes, 32) || IsFlagSet(TrustAttributes, 0x400) || IsFlagSet(TrustAttributes, 0x00400000) || IsFlagSet(TrustAttributes, 0x00800000))
            {
                return "Not applicable";
            }
            // forest trust ?
            if (IsFlagSet(TrustAttributes, 8))
            {
                // quarantined ?
                if (IsFlagSet(TrustAttributes, 4))
                    return "Yes";
                // forest trust migration ?
                else if (IsFlagSet(TrustAttributes, 64))
                    return "No";
                return "Yes";
            }
            // tree root which is obsolete
            else if (IsFlagSet(TrustAttributes, 0x00800000))
            {
                return "Not applicable";
            }
            else
            {
                // quarantined ?
                if (IsFlagSet(TrustAttributes, 4))
                    return "Yes";
                return "No";
            }
        }

        static public string GetTGTDelegation(HealthCheckTrustData trust)
        {
            return GetTGTDelegation(trust.TrustDirection, trust.TrustAttributes);
        }

        static public string GetTGTDelegation(int TrustDirection, int TrustAttributes)
        {
            if (TrustDirection == 0 || TrustDirection == 2)
            {
                return "Not applicable";
            }
            if (IsFlagSet(TrustAttributes, 8))
            {
                // quarantined ?
                if (!IsFlagSet(TrustAttributes, 0x200))
                {
                    if (IsFlagSet(TrustAttributes, 0x800))
                        return "Yes";
                }
                return "No";
            }
            return "Not applicable";
        }

        static public string GetTrustAttribute(int trustAttributes)
        {
            List<string> attributes = new List<string>();
            int value = trustAttributes;
            if (trustAttributes == 0)
                return "None";
            if ((trustAttributes & 0x00800000) != 0)
            {
                attributes.Add("Tree-Root (obsolete)");
                value -= 0x00800000;
            }
            if ((trustAttributes & 0x00400000) != 0)
            {
                attributes.Add("Parent and child (obsolete)");
                value -= 0x00400000;
            }
            if ((trustAttributes & 0x800) != 0)
            {
                attributes.Add("Enable TGT delegation");
                value -= 0x800;
            }
            if ((trustAttributes & 0x400) != 0)
            {
                attributes.Add("PIM Trust");
                value -= 0x400;
            }
            if ((trustAttributes & 0x200) != 0)
            {
                attributes.Add("No TGT delegation allowed");
                value -= 0x200;
            }
            if ((trustAttributes & 128) != 0)
            {
                attributes.Add("RC4");
                value -= 128;
            }
            if ((trustAttributes & 64) != 0)
            {
                attributes.Add("Inter-Forest");
                value -= 64;
            }
            if ((trustAttributes & 32) != 0)
            {
                attributes.Add("Intra-Forest");
                value -= 32;
            }
            if ((trustAttributes & 16) != 0)
            {
                attributes.Add("Cross-Organizational");
                value -= 16;
            }
            if ((trustAttributes & 8) != 0)
            {
                attributes.Add("Forest Trust");
                value -= 8;
            }
            if ((trustAttributes & 4) != 0)
            {
                attributes.Add("Quarantined Domain");
                value -= 4;
            }
            if ((trustAttributes & 2) != 0)
            {
                attributes.Add("Uplevel");
                value -= 2;
            }
            if ((trustAttributes & 1) != 0)
            {
                attributes.Add("Non-Transitive");
                value -= 1;
            }
            if (value != 0)
            {
                attributes.Add("Unknown: 0x" + value.ToString("X"));
            }
            return String.Join(", ", attributes.ToArray());
        }

        static public string GetTrustType(int trustType)
        {
            switch (trustType)
            {
                case 1:
                    return "Downlevel";
                case 2:
                    return "Uplevel";
                case 3:
                    return "MIT";
                case 4:
                    return "DCE";
            }
            return "Unknown: " + trustType.ToString();
        }

        public static string GetTrustDirection(int trustDirection)
        {
            switch (trustDirection)
            {
                case 0:
                    return "Disabled";
                case 1:
                    return "Inbound";
                case 2:
                    return "Outbound";
                case 3:
                    return "Bidirectional";
            }
            return "Unknown: " + trustDirection.ToString();
        }
    }
}
