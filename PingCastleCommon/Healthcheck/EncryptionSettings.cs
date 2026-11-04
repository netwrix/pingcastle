namespace PingCastle.Healthcheck
{
    using System;
    using Microsoft.Graph.Beta.Models;
    using System.Collections.Generic;
    using PingCastleCommon.Options;

    public class ConfigElementsCollection : List<KeySettings>
    {
    }

    public class KeySettings
    {
        public string Name
        {
            get; set;
        }

        public string PublicKey
        {
            get; set;
        }

        public string PrivateKey
        {
            get; set;
        }
    }

    internal class EncryptionSettings
    {
        static EncryptionSettings cachedSettings = null;
        public static EncryptionSettings GetEncryptionSettings()
        {
            if (cachedSettings == null)
            {
                if (ServiceProviderAccessor.IsInitialized)
                {
                    var options = ServiceProviderAccessor.Current.GetService(typeof(Microsoft.Extensions.Options.IOptions<EncryptionOptions>)) as Microsoft.Extensions.Options.IOptions<EncryptionOptions>;
                    cachedSettings = new EncryptionSettings();
                    if (options?.Value != null)
                    {
                        cachedSettings._encryptionKeyValue = options.Value.EncryptionKey;
                        cachedSettings._rsaKeysCollection = new ConfigElementsCollection();
                        foreach (var keyOption in options.Value.RSAKeys)
                        {
                            var keySetting = new KeySettings();
                            keySetting.Name = keyOption.Name;
                            keySetting.PublicKey = keyOption.PublicKey;
                            keySetting.PrivateKey = keyOption.PrivateKey;
                            cachedSettings._rsaKeysCollection.Add(keySetting);
                        }
                    }
                }
                else
                {
                    throw new ApplicationException("Could not load Encryption settings");
                }
            }

            return cachedSettings;
        }

        private string _encryptionKeyValue = string.Empty;
        private ConfigElementsCollection _rsaKeysCollection = null;

        public ConfigElementsCollection RSAKeys => _rsaKeysCollection;

        public string EncryptionKey
        {
            get; set;
        }
    }
}