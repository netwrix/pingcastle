//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
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
        //public static EncryptionSettings settings = 

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
                        RSA.FromXmlString(keyinfo.PublicKey);
                        return RSA;
                    }
                    if (!String.IsNullOrEmpty(keyinfo.PrivateKey))
                    {
                        RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
                        RSA.FromXmlString(keyinfo.PrivateKey);
                        return RSA;
                    }
                }
                throw new ApplicationException("No encryption key set in config file");
            }
            else
            {
                foreach (KeySettings keyinfo in settings.RSAKeys)
                {
                    if (keyinfo.Name == EncryptionKey)
                    {
                        RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
                        if (!String.IsNullOrEmpty(keyinfo.PublicKey))
                            RSA.FromXmlString(keyinfo.PublicKey);
                        else if (!String.IsNullOrEmpty(keyinfo.PrivateKey))
                            RSA.FromXmlString(keyinfo.PrivateKey);
                        else
                            throw new ApplicationException(@"The container """ + EncryptionKey + @""" does not contain a public or a private key");
                        return RSA;
                    }
                }
            }
            throw new ApplicationException("Encryption key not found (name:" + EncryptionKey + ")");
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
            RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
            Console.WriteLine("Public Key (used on the encryption side):");
            Console.WriteLine(@"<encryptionSettings encryptionKey=""default"">
    <RSAKeys>
      <!-- encryption key -->
      <KeySettings name=""default"" publicKey=""" + XmlEscape(RSA.ToXmlString(false)) + @"""/>
      <!--  end -->
    </RSAKeys>
</encryptionSettings>");

            Console.WriteLine("Private Key (used on the decryption side):");
            Console.WriteLine(@"<encryptionSettings encryptionKey=""default"">
    <RSAKeys>
      <!-- decryption key -->
      <KeySettings name=""" + Guid.NewGuid() + @""" privateKey=""" + XmlEscape(RSA.ToXmlString(true)) + @"""/>
      <!--  end -->
    </RSAKeys>
</encryptionSettings>");
            Console.WriteLine("Done");
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
						RSA.FromXmlString(keyinfo.PrivateKey);
					}
					catch (Exception ex)
					{
						throw new ApplicationException("Unable to load the key \"" + keyinfo.Name + "\"", ex);
					}
                    output.Add(RSA);
                }
            }
            return output;
        }
    }
}
