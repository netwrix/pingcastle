//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System.Configuration;

namespace PingCastle
{
    public class ADHealthCheckingLicenseSettings : ConfigurationSection
    {
        private static ADHealthCheckingLicenseSettings settings;

        public static ADHealthCheckingLicenseSettings Settings
        {
            get
            {
                if (settings == null)
                    settings = ConfigurationManager.GetSection("LicenseSettings") as ADHealthCheckingLicenseSettings;
                return settings;
            }
        }

        [ConfigurationProperty("license", IsRequired = false)]
        public string License
        {
            get { return (string)this["license"]; }
            set { this["license"] = value; }
        }
    }
}
