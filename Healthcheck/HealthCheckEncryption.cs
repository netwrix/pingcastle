//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.UserInterface;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Xml;

namespace ADSecurityHealthCheck.Healthcheck
{
    internal class EncryptionSettings : PingCastle.Healthcheck.EncryptionSettings
    {
    }
}

namespace PingCastle.Healthcheck
{
    internal class EncryptionSettings : ConfigurationSection
    {
        static EncryptionSettings cachedSettings = null;
        public static EncryptionSettings GetEncryptionSettings()
        {
            if (cachedSettings == null)
                cachedSettings = ConfigurationManager.GetSection("encryptionSettings") as EncryptionSettings;
            return cachedSettings;
        }


        [ConfigurationProperty("RSAKeys", IsRequired = false)]
        public ConfigElementsCollection RSAKeys
        {
            get
            {
                return base["RSAKeys"] as ConfigElementsCollection;
            }
        }

        [ConfigurationProperty("encryptionKey", IsRequired = false)]
        public string EncryptionKey
        {
            get
            {
                return base["encryptionKey"] as string;
            }
            set
            {
                base["encryptionKey"] = value;
            }
        }

    }

    [ConfigurationCollection(typeof(KeySettings), AddItemName = "KeySettings")]
    public class ConfigElementsCollection : ConfigurationElementCollection
    {
        public ConfigElementsCollection()
        {

        }

        public KeySettings this[int index]
        {
            get { return (KeySettings)BaseGet(index); }
            set
            {
                if (BaseGet(index) != null)
                {
                    BaseRemoveAt(index);
                }
                BaseAdd(index, value);
            }
        }

        public void Add(KeySettings pluginConfig)
        {
            BaseAdd(pluginConfig);
        }

        public void Clear()
        {
            BaseClear();
        }

        protected override ConfigurationElement CreateNewElement()
        {
            return new KeySettings();
        }

        protected override object GetElementKey(ConfigurationElement element)
        {
            return ((KeySettings)element).Name;
        }

        public void Remove(KeySettings pluginConfig)
        {
            BaseRemove(pluginConfig.Name);
        }

        public void RemoveAt(int index)
        {
            BaseRemoveAt(index);
        }

        public void Remove(string name)
        {
            BaseRemove(name);
        }

    }

    public class KeySettings : ConfigurationElement
    {

        [ConfigurationProperty("name", IsKey = true, IsRequired = true)]
        public string Name
        {
            get
            {
                return base["name"] as string;
            }
            set
            {
                base["name"] = value;
            }
        }

        [ConfigurationProperty("publicKey", IsRequired = false)]
        public string PublicKey
        {
            get
            {
                return base["publicKey"] as string;
            }
            set
            {
                base["publicKey"] = value;
            }
        }

        [ConfigurationProperty("privateKey", IsRequired = false)]
        public string PrivateKey
        {
            get
            {
                return base["privateKey"] as string;
            }
            set
            {
                base["privateKey"] = value;
            }
        }

    }

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
                            RSAKeyExtensions.FromXmlStringDotNetCore2(RSA, keyinfo.PublicKey);
                        else if (!String.IsNullOrEmpty(keyinfo.PrivateKey))
                            RSAKeyExtensions.FromXmlStringDotNetCore2(RSA, keyinfo.PrivateKey);
                        else
                            throw new PingCastleException(@"The container """ + EncryptionKey + @""" does not contain a public or a private key");
                        return RSA;
                    }
                }
            }
            throw new PingCastleException("Encryption key not found (name:" + EncryptionKey + ")");
        }

        static string XmlEscape(string unescaped)
        {
            XmlDocument doc = new XmlDocument();
            XmlNode node = doc.CreateElement("root");
            node.InnerText = unescaped;
            return node.InnerXml;
        }

        public static void GenerateRSAKey()
        {
            IUserInterface ui = UserInterfaceFactory.GetUserInterface();

            RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
            ui.DisplayMessage("Public Key (used on the encryption side):");
            ui.DisplayMessage(@"<encryptionSettings encryptionKey=""default"">
    <RSAKeys>
      <!-- encryption key -->
      <KeySettings name=""default"" publicKey=""" + XmlEscape(RSA.ToXmlString(false)) + @"""/>
      <!--  end -->
    </RSAKeys>
</encryptionSettings>");

            ui.DisplayMessage("Private Key (used on the decryption side):");
            ui.DisplayMessage(@"<encryptionSettings encryptionKey=""default"">
    <RSAKeys>
      <!-- decryption key -->
      <KeySettings name=""" + Guid.NewGuid() + @""" privateKey=""" + XmlEscape(RSA.ToXmlString(true)) + @"""/>
      <!--  end -->
    </RSAKeys>
</encryptionSettings>");
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

        public static string ToXmlStringDotNetCore2(RSA rsa, bool includePrivateParameters)
        {
            RSAParameters parameters = rsa.ExportParameters(includePrivateParameters);

            return string.Format("<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent><P>{2}</P><Q>{3}</Q><DP>{4}</DP><DQ>{5}</DQ><InverseQ>{6}</InverseQ><D>{7}</D></RSAKeyValue>",
                  parameters.Modulus != null ? Convert.ToBase64String(parameters.Modulus) : null,
                  parameters.Exponent != null ? Convert.ToBase64String(parameters.Exponent) : null,
                  parameters.P != null ? Convert.ToBase64String(parameters.P) : null,
                  parameters.Q != null ? Convert.ToBase64String(parameters.Q) : null,
                  parameters.DP != null ? Convert.ToBase64String(parameters.DP) : null,
                  parameters.DQ != null ? Convert.ToBase64String(parameters.DQ) : null,
                  parameters.InverseQ != null ? Convert.ToBase64String(parameters.InverseQ) : null,
                  parameters.D != null ? Convert.ToBase64String(parameters.D) : null);
        }

        #endregion
    }
}
