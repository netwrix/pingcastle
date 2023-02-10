//
// Copyright (c) Vincent LE TOUX for Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PingCastle.Cloud.Common
{
    public abstract class JsonSerialization<T>
    {
        public static T LoadFromString(string input)
        {
            /*using (var stream = new MemoryStream())
            {
                var bytes = Encoding.UTF8.GetBytes(input);
                stream.Write(bytes, 0, bytes.Length);
                stream.Position = 0;
                return LoadFromStream(stream);
            }*/

            return JsonConvert.DeserializeObject<T>(input);
        }
        public static T LoadFromStream(Stream input)
        {
            /*T t;
            var serializer = new DataContractJsonSerializer(typeof(T));

            t = (T)serializer.ReadObject(input);
            */
            using (StreamReader sr = new StreamReader(input))
            using (JsonReader reader = new JsonTextReader(sr))
            {
                JsonSerializer serializer = new JsonSerializer();
                return (T) serializer.Deserialize(reader, typeof(T));
            }
        }

        public string ToJsonString()
        {
            return JsonConvert.SerializeObject(this);
            /*
            var serializer = new DataContractJsonSerializer(typeof(T));
            using (var ms = new MemoryStream())
            {
                serializer.WriteObject(ms, this);
                var buf = ms.ToArray();
                return Encoding.UTF8.GetString(buf);
            }*/
        }

        public string ToBase64JsonString()
        {
            var data = JsonConvert.SerializeObject(this);
            var payloadString = Encoding.UTF8.GetBytes(data);
            return Convert.ToBase64String(payloadString);
        }

        public string ToBase64UrlJsonString()
        {
            return ToBase64JsonString()
                .Replace("=", "")
                .Replace("/", "_")
                .Replace("+", "-")
                .Replace("=", "");
        }

        public static T LoadFromBase64String(string payload)
        {
            var payloadBytes = Convert.FromBase64String(payload.PadRight(payload.Length + (payload.Length * 3) % 4, '='));
            var payloadString = Encoding.UTF8.GetString(payloadBytes);
            return JsonConvert.DeserializeObject<T>(payloadString);
            /*T t;
            var serializer = new DataContractJsonSerializer(typeof(T));
            using (var stream = new MemoryStream())
            {
                stream.Write(payloadString, 0, payloadString.Length);
                stream.Position = 0;
                t = (T)serializer.ReadObject(stream);
            }

            return t;*/
        }
    }
}
