//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Diagnostics;
using System.Text.RegularExpressions;

namespace PingCastle.Data
{
    [DebuggerDisplay("FQDN: {DomainName} SID: {DomainSID} NetBIOS: {DomainNetBIOS}")]
    public class DomainKey : IComparable<DomainKey>, IEquatable<DomainKey>
    {
        public string DomainName { get; set; }
        public string DomainSID { get; set; }
        public string DomainNetBIOS { get; set; }
        public bool IsComplete { get { return DomainSID != null && DomainName != null && DomainNetBIOS != null; } }

        private DomainKey()
        {
        }

        static Regex sidRegex = new Regex(@"(^$|^S-\d-(\d+-){1,14}\d+$)");

        public static DomainKey Create(string DnsName, string domainSid, string domainNetbios)
        {
            var key = new DomainKey(DnsName, domainSid, domainNetbios);
            if (key.DomainSID == null && key.DomainNetBIOS == key.DomainSID && key.DomainName == key.DomainNetBIOS)
            {
                return null;
            }
            return key;
        }

        protected DomainKey(string DnsName, string domainSid, string domainNetbios)
        {

            if (!string.IsNullOrEmpty(DnsName))
            {
                // SID History data stored the SID in the FQDN field
                if (domainSid != DnsName)
                    DomainName = DnsName.ToLowerInvariant();
            }
            if (!string.IsNullOrEmpty(domainSid))
            {
                if (sidRegex.IsMatch(domainSid))
                {
                    DomainSID = domainSid;
                }
                else
                {
                    Trace.WriteLine("Unable to parse the SID " + domainSid);
                    throw new PingCastleException("Unable to parse the SID \"" + domainSid + "\" - it should be like S-1-5-21-3777291851-731158365-1300944990");
                }
            }
            if (!string.IsNullOrEmpty(domainNetbios))
                DomainNetBIOS = domainNetbios.ToUpperInvariant();
        }

        public override bool Equals(object obj)
        {
            if (obj == null)
                return false;
            DomainKey d = obj as DomainKey;
            if (d == null)
                return false;
            return Equals(d);
        }

        // enrich the domain at each comparaison
        public bool Equals(DomainKey d)
        {

            if (!string.IsNullOrEmpty(DomainSID) && !string.IsNullOrEmpty(d.DomainSID))
                return string.Equals(DomainSID, d.DomainSID, StringComparison.InvariantCultureIgnoreCase);
            // important:
            // if a SID is being associated to one domain, propagate this information
            if (string.Equals(DomainName, d.DomainName, StringComparison.InvariantCultureIgnoreCase))
            {
                if (DomainSID == null && d.DomainSID != null)
                    DomainSID = d.DomainSID;
                if (DomainSID != null && d.DomainSID == null)
                    d.DomainSID = DomainSID;
                return true;
            }
            return false;
        }

        public static bool operator ==(DomainKey a, DomainKey b)
        {
            // If both are null, or both are same instance, return true.
            if (Object.ReferenceEquals(a, b))
            {
                return true;
            }

            // If one is null, but not both, return false.
            if (((object)a == null) || ((object)b == null))
            {
                return false;
            }

            // Return true if the fields match:
            return a.Equals(b);
        }
        public static bool operator !=(DomainKey a, DomainKey b)
        {
            return !(a == b);
        }

        public override int GetHashCode()
        {
            return DomainName.GetHashCode();
        }
        public int CompareTo(DomainKey other)
        {
            int res = String.Compare(DomainName, other.DomainName, true);
            if (res == 0 && !String.IsNullOrEmpty(DomainSID) && !String.IsNullOrEmpty(other.DomainSID))
                res = String.Compare(DomainSID, other.DomainSID, true);
            else
            {
                // if a SID is being associated to one domain, propagate this information
                if (DomainSID == null && other.DomainSID != null)
                    DomainSID = other.DomainSID;
                if (DomainSID != null && other.DomainSID == null)
                    other.DomainSID = DomainSID;
            }
            return res;
        }

        public override string ToString()
        {
            if (DomainSID == null)
                return DomainName;
            return DomainName + " (" + DomainSID.ToUpperInvariant() + ")";
        }

        public static bool IsDuplicateNameButNotDuplicateDomain(DomainKey a, DomainKey b)
        {
            return (a != null && b != null && String.Compare(a.DomainName, b.DomainName, StringComparison.InvariantCultureIgnoreCase) == 0
                    && a.DomainSID != null && b.DomainSID != null
                    && a.DomainSID != b.DomainSID);
        }

    }
}
