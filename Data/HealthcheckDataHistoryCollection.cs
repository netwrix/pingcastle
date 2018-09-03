//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.Security.Principal;
using System.Text;

namespace PingCastle.Healthcheck
{
    public class HealthcheckDataHistoryCollection : ICollection<HealthcheckData>
    {

        Dictionary<string, Dictionary<DateTime, HealthcheckData>> data { get; set; }

        public HealthcheckDataHistoryCollection()
        {
            data = new Dictionary<string, Dictionary<DateTime, HealthcheckData>>();
        }

        public void Add(HealthcheckData item)
        {
            // taking the more recent report
            var sid = item.DomainSid;
            if (!data.ContainsKey(sid))
            {
                data[sid] = new Dictionary<DateTime, HealthcheckData>();
            }
            data[sid][item.GenerationDate] = item;
        }

        public void Clear()
        {
            data.Clear();
        }

        public bool Contains(HealthcheckData item)
        {
            var sid = item.DomainSid;
            return data.ContainsKey(sid) && data[sid].ContainsKey(item.GenerationDate);
        }

        public void CopyTo(HealthcheckData[] array, int arrayIndex)
        {
            foreach (var value in data.Values)
            {
                value.Values.CopyTo(array, arrayIndex);
                arrayIndex += value.Count;
            }
        }

        public int Count
        {
            get
            {
                int count = 0;
                foreach (var value in data.Values)
                {
                    count += value.Count;
                }
                return count;
            }
        }

        public bool IsReadOnly
        {
            get { return false; }
        }

        public bool Remove(HealthcheckData item)
        {
            var sid = item.DomainSid;
            if (!data.ContainsKey(sid))
                return false;
            var value = data[sid];
            if (!value.ContainsKey(item.GenerationDate))
                return false;
            value.Remove(item.GenerationDate);
            return true;
        }

        public IEnumerator<HealthcheckData> GetEnumerator()
        {
            throw new NotImplementedException();
        }

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
        {
            return this.GetEnumerator();
        }

        public IEnumerable<KeyValuePair<string, DateTime>> GetKeyPoints()
        {
            var output = new List<KeyValuePair<string, DateTime>>();
            foreach (var sid in data.Keys)
            {
                foreach (var date in data[sid].Keys)
                {
                    output.Add(new KeyValuePair<string, DateTime>(sid, date));
                }
            }
            return output;
        }

        public HealthcheckData GetItem(KeyValuePair<string, DateTime> key)
        {
            return data[key.Key][key.Value];
        }

        public HealthcheckDataCollection GetDataReportAtDate(DateTime dateToIssueReport)
        {
            var output = new HealthcheckDataCollection();
            foreach (var sid in data.Keys)
            {
                DateTime min = DateTime.MinValue;
                foreach (var date in data[sid].Keys)
                {
                    if (date > min && date <= dateToIssueReport)
                        min = date;
                }
                if (min != DateTime.MinValue)
                    output.Add(data[sid][min]);
            }
            return output;
        }

        public DateTime MinDate
        {
            get
            {
                DateTime min = DateTime.MaxValue;
                foreach (var sid in data.Keys)
                {
                    foreach (var date in data[sid].Keys)
                    {
                        if (date < min)
                            min = date;
                    }
                }
                return min;
            }
        }

        public DateTime MaxDate
        {
            get
            {
                DateTime max = DateTime.MinValue;
                foreach (var sid in data.Keys)
                {
                    foreach (var date in data[sid].Keys)
                    {
                        if (date > max)
                            max = date;
                    }
                }
                return max;
            }
        }
    }
}
