//
// Copyright (c) Vincent LE TOUX for Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.IO;

namespace PingCastle.Cloud.Tokens
{
    public class TokenCache
    {
        const string DirectoryName = "Cache";
        public static List<Token> GetTokens()
        {
            var output = new List<Token>();
            foreach (var file in Directory.EnumerateFiles(DirectoryName, "*.json"))
            {
                output.Add(Token.LoadFromString(File.ReadAllText(file)));
            }
            return output;
        }

        public static void Save(Token token)
        {
            if (!Directory.Exists(DirectoryName))
                Directory.CreateDirectory(DirectoryName);
            File.WriteAllText(Path.Combine(DirectoryName, token .resource.Replace("https://", "").Replace("/", "") + "-" + Guid.NewGuid() + ".json"), token.ToJsonString());
        }
    }
}
