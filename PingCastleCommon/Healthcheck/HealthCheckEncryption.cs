//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.UserInterface;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using System.Xml;

namespace PingCastle.Healthcheck
{
    public class HealthCheckEncryption
    {
        public static RSA GetRSAEncryptionKey()
        {
            EncryptionSettings settings = EncryptionSettings.GetEncryptionSettings();
            string EncryptionKey = settings.EncryptionKey;
            if (String.IsNullOrEmpty(EncryptionKey))
            {
                foreach (KeySettings keyinfo in settings.RSAKeys)
                {
                    if (!String.IsNullOrEmpty(keyinfo.PublicKey))
                    {
                        RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
                        RSAKeyExtensions.FromXmlStringDotNetCore2(RSA, keyinfo.PublicKey);
                        return RSA;
                    }

                    if (!String.IsNullOrEmpty(keyinfo.PrivateKey))
                    {
                        RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
                        RSAKeyExtensions.FromXmlStringDotNetCore2(RSA, keyinfo.PrivateKey);
                        return RSA;
                    }
                }

                throw new PingCastleException("No encryption key set in config file");
            }
            else
            {
                foreach (KeySettings keyinfo in settings.RSAKeys)
                {
                    if (keyinfo.Name == EncryptionKey)
                    {
                        RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
                        if (!String.IsNullOrEmpty(keyinfo.PublicKey))
                        {
                            RSAKeyExtensions.FromXmlStringDotNetCore2(RSA, keyinfo.PublicKey);
                        }
                        else if (!String.IsNullOrEmpty(keyinfo.PrivateKey))
                        {
                            RSAKeyExtensions.FromXmlStringDotNetCore2(RSA, keyinfo.PrivateKey);
                        }
                        else
                        {
                            throw new PingCastleException(@"The container """ + EncryptionKey + @""" does not contain a public or a private key");
                        }

                        return RSA;
                    }
                }
            }

            throw new PingCastleException("Encryption key not found (name:" + EncryptionKey + ")");
        }

        public static void GenerateRSAKey()
        {
            IUserInterface ui = UserInterfaceFactory.GetUserInterface();

            RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();

            ui.DisplayMessage("Public Key (used on the encryption side):");
            var publicKeyConfig = new
            {
                Encryption = new
                {
                    EncryptionKey = "default",
                    RSAKeys = new[]
                    {
                        new
                        {
                            Name = "default",
                            PublicKey = RSA.ToXmlString(false)
                        }
                    }
                }
            };
            ui.DisplayMessage(JsonSerializer.Serialize(publicKeyConfig, new JsonSerializerOptions { WriteIndented = true }));

            ui.DisplayMessage("Private Key (used on the decryption side):");
            var privateKeyConfig = new
            {
                Encryption = new
                {
                    EncryptionKey = "default",
                    RSAKeys = new[]
                    {
                        new
                        {
                            Name = Guid.NewGuid().ToString(),
                            PrivateKey = RSA.ToXmlString(true)
                        }
                    }
                }
            };
            ui.DisplayMessage(JsonSerializer.Serialize(privateKeyConfig, new JsonSerializerOptions { WriteIndented = true }));

            ui.DisplayMessage("Done");
        }

        public static List<RSA> GetAllPrivateKeys()
        {
            List<RSA> output = new List<RSA>();
            EncryptionSettings settings = EncryptionSettings.GetEncryptionSettings();
            if (settings == null)
            {
                Trace.WriteLine("No encryption setting found in config file");
                return output;
            }

            foreach (KeySettings keyinfo in settings.RSAKeys)
            {
                if (!String.IsNullOrEmpty(keyinfo.PrivateKey))
                {
                    Trace.WriteLine("Loading key " + keyinfo.Name);
                    RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
                    try
                    {
                        RSAKeyExtensions.FromXmlStringDotNetCore2(RSA, keyinfo.PrivateKey);
                    }
                    catch (Exception ex)
                    {
                        throw new PingCastleException("Unable to load the key \"" + keyinfo.Name + "\"", ex);
                    }

                    output.Add(RSA);
                }
            }

            return output;
        }
    }

    internal static class RSAKeyExtensions
    {
        #region XML

        public static void FromXmlStringDotNetCore2(RSA rsa, string xmlString)
        {
            RSAParameters parameters = new RSAParameters();

            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.LoadXml(xmlString);

            if (xmlDoc.DocumentElement.Name.Equals("RSAKeyValue"))
            {
                foreach (XmlNode node in xmlDoc.DocumentElement.ChildNodes)
                {
                    switch (node.Name)
                    {
                        case "Modulus": parameters.Modulus = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "Exponent": parameters.Exponent = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "P": parameters.P = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "Q": parameters.Q = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "DP": parameters.DP = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "DQ": parameters.DQ = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "InverseQ": parameters.InverseQ = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "D": parameters.D = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                    }
                }
            }
            else
            {
                throw new Exception("Invalid XML RSA key.");
            }

            rsa.ImportParameters(parameters);
        }

        #endregion
    }
}
