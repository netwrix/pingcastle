//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;

namespace PingCastle.Data
{

    public class PingCastleReportCollection<T> : ICollection<T> where T : IPingCastleReport
    {
        Dictionary<string, T> data { get; set; }
        // database of FQDN, all SID
        Dictionary<string, List<string>> AmbigiousNameReference { get; set; }
        Dictionary<string, DomainKey> DomainReference { get; set; }

        public PingCastleReportCollection()
        {
            data = new Dictionary<string, T>();
            AmbigiousNameReference = new Dictionary<string, List<string>>();
            DomainReference = new Dictionary<string, DomainKey>();
        }

        public void Add(T item)
        {
            if (item == null)
                return;
            // taking the more recent report
            var sid = item.Domain.DomainSID;
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

        }

        public void EnrichInformation()
        {
            // complete domain information
            // indeed, data can be FQDN only (trust with remote deleted)
            // NetBIOS + SID (SID History and unable to locate a server)
            // SID Only (SID History from removed domain)
            AmbigiousNameReference.Clear();

            var sidreference = new Dictionary<string, DomainKey>();

            // first pass - build reference based on SID
            foreach (var item in data.Values)
            {
                foreach (var domainKey in item.DomainKnown)
                {
                    if (domainKey.IsComplete && !sidreference.ContainsKey(domainKey.DomainSID))
                    {
                        sidreference.Add(domainKey.DomainSID, domainKey);
                    }
                }
            }
            // second pass, build AmbigiousNameReference
            foreach (var domain in sidreference.Values)
            {
                if (!AmbigiousNameReference.ContainsKey(domain.DomainName))
                    AmbigiousNameReference[domain.DomainName] = new List<string> { domain.DomainSID };
                else if (!string.IsNullOrEmpty(domain.DomainSID))
                    if (!AmbigiousNameReference[domain.DomainName].Contains(domain.DomainSID))
                        AmbigiousNameReference[domain.DomainName].Add(domain.DomainSID);
            }
            // third pass, update incomplete information based on the information we have
            foreach (var item in data.Values)
            {
                foreach (var domainKey in item.DomainKnown)
                {
                    if (domainKey.IsComplete)
                    {
                        continue;
                    }
                    // try to complete based on sid
                    if (!String.IsNullOrEmpty(domainKey.DomainSID) && sidreference.ContainsKey(domainKey.DomainSID))
                    {
                        var reference = sidreference[domainKey.DomainSID];
                        if (string.IsNullOrEmpty(domainKey.DomainNetBIOS))
                            domainKey.DomainNetBIOS = reference.DomainNetBIOS;
                        if (string.IsNullOrEmpty(domainKey.DomainName))
                            domainKey.DomainName = reference.DomainName;
                    }
                    else if (!String.IsNullOrEmpty(domainKey.DomainName))
                    {
                        foreach (var reference in sidreference.Values)
                        {
                            if (reference.DomainName == domainKey.DomainName)
                            {
                                if (string.IsNullOrEmpty(domainKey.DomainNetBIOS))
                                    domainKey.DomainNetBIOS = reference.DomainNetBIOS;
                                break;
                            }
                        }
                    }
                    else if (!String.IsNullOrEmpty(domainKey.DomainNetBIOS))
                    {
                        foreach (var reference in sidreference.Values)
                        {
                            if (reference.DomainNetBIOS == domainKey.DomainNetBIOS)
                            {
                                if (string.IsNullOrEmpty(domainKey.DomainName))
                                {
                                    domainKey.DomainName = reference.DomainName;
                                }
                                if (string.IsNullOrEmpty(domainKey.DomainName))
                                    domainKey.DomainName = reference.DomainName;
                                break;
                            }
                        }
                    }
                }
            }
        }

        public void Clear()
        {
            data.Clear();
        }

        public bool Contains(T item)
        {
            return data.ContainsValue(item);
        }

        public void CopyTo(T[] array, int arrayIndex)
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

        public bool Remove(T item)
        {
            if (item == null)
                return false;
            return data.Remove(item.Domain.DomainSID);
        }

        public IEnumerator<T> GetEnumerator()
        {
            return data.Values.GetEnumerator();
        }

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
        {
            return data.Values.GetEnumerator();
        }

        public T GetDomain(DomainKey key)
        {
            if (key == null)
                return default(T);
            if (key.DomainSID != null)
            {
                if (data.ContainsKey(key.DomainSID))
                    return data[key.DomainSID];
                return default(T);
            }
            foreach (T hc in data.Values)
            {
                if (string.Equals(hc.Domain.DomainName, key.DomainName, StringComparison.InvariantCultureIgnoreCase))
                    return hc;
            }
            return default(T);
        }

        public bool HasDomainAmbigiousName(DomainKey domainKey)
        {
            if (domainKey == null || string.IsNullOrEmpty(domainKey.DomainName))
                return false;
            if (AmbigiousNameReference.ContainsKey(domainKey.DomainName))
                return AmbigiousNameReference[domainKey.DomainName].Count > 1;
            return true;
        }

    }
}
