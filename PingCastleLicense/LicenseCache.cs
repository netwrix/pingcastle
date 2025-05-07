using System;

namespace PingCastle.PingCastleLicense
{
    public class LicenseCache
    {
        private ADHealthCheckingLicense _license;
        private static LicenseCache _instance;

        private LicenseCache() { }

        public static LicenseCache Instance
        {
            get
            {
                if (_instance == null)
                {
                    _instance = new LicenseCache();
                }
                return _instance;
            }
        }

        public ADHealthCheckingLicense GetLicense()
        {
            return _license;
        }

        public void StoreLicense(ADHealthCheckingLicense license)
        {
            if (license == null)
            {
                throw new ArgumentException("License cannot be null.");
            }

            _license = license;
        }
    }

}
