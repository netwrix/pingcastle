//
// Copyright (c) Vincent LE TOUX for Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.IO;
using System.Text;
using System.Text.Json;

namespace PingCastle.Cloud.Common
{
    public abstract class JsonSerialization<T>
    {
        public static T LoadFromString(string input)
        {
            return JsonSerializer.Deserialize<T>(input) ?? throw new InvalidOperationException("Failed to deserialize JSON");
        }

        public static T LoadFromStream(Stream input)
        {
            using (StreamReader sr = new StreamReader(input))
            {
                var content = sr.ReadToEnd();
                return JsonSerializer.Deserialize<T>(content) ?? throw new InvalidOperationException("Failed to deserialize JSON");
            }
        }

        public string ToJsonString()
        {
            return JsonSerializer.Serialize(this, GetType());
        }

        public string ToBase64JsonString()
        {
            var data = JsonSerializer.Serialize(this, GetType());
            var payloadString = Encoding.UTF8.GetBytes(data);
            return Convert.ToBase64String(payloadString);
        }

        public string ToBase64UrlJsonString()
        {
            return ToBase64JsonString()
                .Replace("=", "")
                .Replace("/", "_")
                .Replace("+", "-");
        }

        public static T LoadFromBase64String(string payload)
        {
            var payloadBytes = Convert.FromBase64String(payload.PadRight(payload.Length + (payload.Length * 3) % 4, '='));
            var payloadString = Encoding.UTF8.GetString(payloadBytes);
            return JsonSerializer.Deserialize<T>(payloadString) ?? throw new InvalidOperationException("Failed to deserialize JSON");
        }
    }
}
