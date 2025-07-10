using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace PingCastle.misc
{
    public static class Extensions
    {
        public static async Task<Dictionary<TKey, TValue>> ToDictionaryAsync<TKey, TValue>(this IAsyncEnumerable<TValue> collection, Func<TValue, TKey> key)
        {
            var dictionary = new Dictionary<TKey, TValue>();

            await foreach (var item in collection)
            {
                dictionary[key(item)] = item;
            }

            return dictionary;
        }

        public static async Task<List<TValue>> ToListAsync<TValue>(this IAsyncEnumerable<TValue> collection)
        {
            var list = new List<TValue>();

            await foreach (var item in collection)
            {
                list.Add(item);
            }

            return list;
        }
    }
}
