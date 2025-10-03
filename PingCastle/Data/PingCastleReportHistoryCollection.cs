//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Data;
using System;
using System.Collections.Generic;

namespace PingCastle.Healthcheck
{
    public class PingCastleReportHistoryCollection<T> : ICollection<T> where T : IPingCastleReport
    {

        Dictionary<string, Dictionary<DateTime, T>> data { get; set; }

        public PingCastleReportHistoryCollection()
        {
            data = new Dictionary<string, Dictionary<DateTime, T>>();
        }

        public void Add(T item)
        {
            // taking the more recent report
            var sid = item.Domain.DomainSID;
            if (!data.ContainsKey(sid))
            {
                data[sid] = new Dictionary<DateTime, T>();
            }
            data[sid][item.GenerationDate] = item;
        }

        public void Clear()
        {
            data.Clear();
        }

        public bool Contains(T item)
        {
            var sid = item.Domain.DomainSID;
            return data.ContainsKey(sid) && data[sid].ContainsKey(item.GenerationDate);
        }

        public void CopyTo(T[] array, int arrayIndex)
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

        public bool Remove(T item)
        {
            var sid = item.Domain.DomainSID;
            if (!data.ContainsKey(sid))
                return false;
            var value = data[sid];
            if (!value.ContainsKey(item.GenerationDate))
                return false;
            value.Remove(item.GenerationDate);
            return true;
        }

        public IEnumerator<T> GetEnumerator()
        {
            throw new NotImplementedException();
        }

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
        {
            return this.GetEnumerator();
        }

        public PingCastleReportCollection<T> ToLatestReportCollection()
        {
            var output = new PingCastleReportCollection<T>();
            foreach (var sid in data.Keys)
            {
                DateTime maxDate = DateTime.MinValue;
                foreach (var date in data[sid].Keys)
                {
                    if (maxDate < date)
                        maxDate = date;
                }
                output.Add(data[sid][maxDate]);
            }
            output.EnrichInformation();
            return output;
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

        public T GetItem(KeyValuePair<string, DateTime> key)
        {
            return data[key.Key][key.Value];
        }

        public PingCastleReportCollection<T> GetDataReportAtDate(DateTime dateToIssueReport)
        {
            var output = new PingCastleReportCollection<T>();
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
            output.EnrichInformation();
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
