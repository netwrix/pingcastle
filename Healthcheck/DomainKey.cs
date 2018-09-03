//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;

namespace PingCastle.Healthcheck
{
    [DebuggerDisplay("{DomainName} {DomainSID}")]
    public class DomainKey : IComparable<DomainKey>, IEquatable<DomainKey>
    {
        public string DomainName { get; set; }
        public string DomainSID { get; set; }

        private DomainKey()
        {
        }

        static Regex sidRegex = new Regex(@"(^$|^S-\d-(\d+-){1,14}\d+$)");

        public DomainKey(string DnsName, string domainSid)
        {
            this.DomainName = DnsName;
            if (!String.IsNullOrEmpty(this.DomainName))
                this.DomainName = this.DomainName.ToLowerInvariant();
            if (!String.IsNullOrEmpty(domainSid))
            {
                if (sidRegex.IsMatch(domainSid))
                {
                    this.DomainSID = domainSid;
                }
                else
                {
                    Trace.WriteLine("Unable to parse the SID " + domainSid);
                    throw new ApplicationException("Unable to parse the SID \"" + domainSid + "\" - it should be like S-1-5-21-3777291851-731158365-1300944990");
                }
            }
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

            if (!String.IsNullOrEmpty(DomainSID) && !String.IsNullOrEmpty(d.DomainSID))
                return String.Equals(DomainSID, d.DomainSID, StringComparison.InvariantCultureIgnoreCase) ;
            // important:
            // if a SID is being associated to one domain, propagate this information
            if (String.Equals(DomainName, d.DomainName, StringComparison.InvariantCultureIgnoreCase))
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
            if (System.Object.ReferenceEquals(a, b))
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
			return ( a !=null && b != null && String.Compare(a.DomainName, b.DomainName, StringComparison.InvariantCultureIgnoreCase) == 0
					&& a.DomainSID != null && b.DomainSID != null
					&& a.DomainSID != b.DomainSID);
		}

    }
}
