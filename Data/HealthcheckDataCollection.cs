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

namespace PingCastle.Healthcheck
{

    public class HealthcheckDataCollection : ICollection<HealthcheckData>
    {
        Dictionary<string, HealthcheckData> data { get; set; }
        Dictionary<string, List<string>> AmbigiousNameReference { get; set; }

        public HealthcheckDataCollection()
        {
            data = new Dictionary<string, HealthcheckData>();
            AmbigiousNameReference = new Dictionary<string, List<string>>();
        }

        public void Add(HealthcheckData item)
        {
            // taking the more recent report
            var sid = item.DomainSid;
            if (data.ContainsKey(sid))
            {
                if (data[sid].GenerationDate < item.GenerationDate)
                {
                    data[sid] = item;
                }
            }
            else
            {
                data.Add(sid, item);
            }
            UpdateAmbigiousReference(item.Domain);
            foreach(var t in item.Trusts)
            {
                UpdateAmbigiousReference(t.Domain);
                foreach(var d in t.KnownDomains)
                {
                    UpdateAmbigiousReference(d.Domain);
                    UpdateAmbigiousReference(d.Forest);
                }
            }
            foreach(var d in item.ReachableDomains)
            {
                UpdateAmbigiousReference(d.Domain);
                UpdateAmbigiousReference(d.Forest);
            }
        }

        private void UpdateAmbigiousReference(DomainKey domain)
        {
            if (domain == null || String.IsNullOrEmpty(domain.DomainSID) || String.IsNullOrEmpty(domain.DomainName))
                return;
            if (!AmbigiousNameReference.ContainsKey(domain.DomainName))
                AmbigiousNameReference[domain.DomainName] = new List<string> { domain.DomainSID };
            else if (!String.IsNullOrEmpty(domain.DomainSID))
                if (!AmbigiousNameReference[domain.DomainName].Contains(domain.DomainSID))
                    AmbigiousNameReference[domain.DomainName].Add(domain.DomainSID);
        }

        public void Clear()
        {
            data.Clear();
        }

        public bool Contains(HealthcheckData item)
        {
            return data.ContainsValue(item);
        }

        public void CopyTo(HealthcheckData[] array, int arrayIndex)
        {
 	        data.Values.CopyTo(array, arrayIndex);
        }

        public int Count
        {
            get { return data.Count; }
        }

        public bool IsReadOnly
        {
	        get { return false; }
        }

        public bool Remove(HealthcheckData item)
        {
 	        return data.Remove(item.DomainSid);
        }

        public IEnumerator<HealthcheckData> GetEnumerator()
        {
 	        return data.Values.GetEnumerator();
        }

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
        {
 	        return data.Values.GetEnumerator();
        }

        public HealthcheckData GetDomain(DomainKey key)
        {
            if (key.DomainSID != null)
            {
                if (data.ContainsKey(key.DomainSID))
                    return data[key.DomainSID];
                return null;
            }
            foreach (HealthcheckData hc in data.Values)
            {
                if (String.Equals(hc.DomainFQDN, key.DomainName, StringComparison.InvariantCultureIgnoreCase))
                    return hc;
            }
            return null;
        }

        public bool HasDomainAmbigiousName(DomainKey domainKey)
        {
            if (AmbigiousNameReference.ContainsKey(domainKey.DomainName))
                return AmbigiousNameReference[domainKey.DomainName].Count > 1;
            return true;
        }

    }
}
