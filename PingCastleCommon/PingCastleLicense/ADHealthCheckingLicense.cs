namespace PingCastle
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel;
    using System.Diagnostics;
    using System.IO;
    using System.IO.Compression;
    using System.Security.Cryptography;
    using System.Text;
    using System.Text.RegularExpressions;

    public class ADHealthCheckingLicense : License, IDisposable
    {
        private readonly string _licKey = null;
        private bool _disposed = false;
        private string _edition;
        private bool _isV3License = false;
        private List<Regex> _compiledDomainPatterns;
        private int? _licensedUserCount = null;
        private string _licenseStatus = "Normal";
        private bool _isVerified = false;

        public ADHealthCheckingLicense(string license)
        {
            if (string.IsNullOrEmpty(license))
            {
                throw new PingCastleException("No PingCastle license has been provided");
            }

            _licKey = license;
        }

        public void Verify()
        {
            Trace.WriteLine("License: " + _licKey);
            _isVerified = true;
            if (!VerifyKey())
            {
                throw new PingCastleException("The PingCastle license is not valid");
            }

            InitializeDomainPatterns();
        }

        protected virtual bool IsVerified
        {
            get { return _isVerified; }
        }

        private DateTime _endTime;
        public DateTime EndTime
        {
            get
            {
                if (!IsVerified)
                {
                    throw new PingCastleException("License has not been verified. Call Verify() first.");
                }

                return _endTime;
            }
            set => _endTime = value;
        }

        private string _domainLimitation;
        public string DomainLimitation
        {
            get
            {
                if (!IsVerified)
                {
                    throw new PingCastleException("License has not been verified. Call Verify() first.");
                }

                return _domainLimitation;
            }
            set => _domainLimitation = value;
        }

        private string _customerNotice;
        public string CustomerNotice
        {
            get
            {
                if (!IsVerified)
                {
                    throw new PingCastleException("License has not been verified. Call Verify() first.");
                }

                return _customerNotice;
            }
            set => _customerNotice = value;
        }

        public string Edition
        {
            get
            {
                if (!IsVerified)
                {
                    throw new PingCastleException("License has not been verified. Call Verify() first.");
                }

                return string.IsNullOrEmpty(_edition) ? "Basic" : _edition;
            }
            set => _edition = value;
        }

        private int? _domainNumberLimit;
        public int? DomainNumberLimit
        {
            get
            {
                if (!IsVerified)
                {
                    throw new PingCastleException("License has not been verified. Call Verify() first.");
                }

                return _domainNumberLimit;
            }
            set => _domainNumberLimit = value;
        }

        public int? LicensedUserCount
        {
            get
            {
                if (!IsVerified)
                {
                    throw new PingCastleException("License has not been verified. Call Verify() first.");
                }

                return _licensedUserCount;
            }
        }

        public string LicenseStatus
        {
            get
            {
                if (!IsVerified)
                {
                    throw new PingCastleException("License has not been verified. Call Verify() first.");
                }

                return _licenseStatus;
            }
        }

        /// <summary>
        /// Gets the license key granted to this component.
        /// </summary>
        public override string LicenseKey
        {
            get
            {
                if (!IsVerified)
                {
                    throw new PingCastleException("License has not been verified. Call Verify() first.");
                }

                return _licKey;
            }
        }

        protected virtual bool VerifyKey()
        {
            try
            {
                Trace.WriteLine("starting the license analysis");

                Trace.WriteLine("License info uncompressed");

                if (_licKey != null && _licKey.StartsWith("PC3"))
                {
                    VerifyLicenseV3();
                }
                else if (_licKey != null && _licKey.StartsWith("PC2"))
                {
                    VerifyLicenseV2();
                }
                else
                {
                    VerifyLicenseV1();
                }

                return true;
            }
            catch (Exception ex)
            {
                Trace.Write("License: exception " + ex.Message);
                return false;
            }
        }

        private void VerifyLicenseV3()
        {
            byte[] b = Convert.FromBase64String(_licKey.Substring(3));
            using (MemoryStream ms = new MemoryStream(b))
            {
                using (GZipStream gs = new GZipStream(ms, CompressionMode.Decompress))
                {
                    using (var ms2 = new MemoryStream())
                    {
                        while (true)
                        {
                            int infoType = readint(gs);
                            int infoLength = readint(gs);
                            byte[] data = new byte[infoLength];
                            gs.Read(data, 0, data.Length);
                            Trace.WriteLine("data Type = " + infoType);
                            switch (infoType)
                            {
                                case 0:
                                    Trace.WriteLine("Signature");
                                    VerifySignature(data, ms2.ToArray());
                                    if (Edition == "Pro" && DomainNumberLimit == null)
                                    {
                                        DomainNumberLimit = 1;
                                    }

                                    _isV3License = true;
                                    return;
                                case 1:
                                    Trace.WriteLine("EndTime");
                                    EndTime = DateTime.FromFileTimeUtc(BitConverter.ToInt64(data, 0));
                                    break;
                                case 2:
                                    Trace.WriteLine("DomainLimitation");
                                    DomainLimitation = Encoding.Unicode.GetString(data);
                                    break;
                                case 3:
                                    Trace.WriteLine("CustomerNotice");
                                    CustomerNotice = Encoding.Unicode.GetString(data);
                                    break;
                                case 4:
                                    Trace.WriteLine("Edition");
                                    Edition = Encoding.Unicode.GetString(data);
                                    break;
                                case 5:
                                    DomainNumberLimit = BitConverter.ToInt32(data, 0);
                                    break;
                                case 6:
                                    Trace.WriteLine("LicensedUserCount");
                                    _licensedUserCount = BitConverter.ToInt32(data, 0);
                                    break;
                            }

                            ms2.Write(BitConverter.GetBytes(infoType), 0, 4);
                            ms2.Write(BitConverter.GetBytes(data.Length), 0, 4);
                            ms2.Write(data, 0, data.Length);
                        }
                    }
                }
            }
        }

        private void VerifyLicenseV2()
        {
            byte[] b = Convert.FromBase64String(_licKey.Substring(3));
            using (MemoryStream ms = new MemoryStream(b))
            {
                using (GZipStream gs = new GZipStream(ms, CompressionMode.Decompress))
                {
                    using (var ms2 = new MemoryStream())
                    {
                        while (true)
                        {
                            int infoType = readint(gs);
                            int infoLength = readint(gs);
                            byte[] data = new byte[infoLength];
                            gs.Read(data, 0, data.Length);
                            Trace.WriteLine("data Type = " + infoType);
                            switch (infoType)
                            {
                                case 0:
                                    Trace.WriteLine("Signature");
                                    VerifySignature(data, ms2.ToArray());
                                    if (Edition == "Pro" && DomainNumberLimit == null)
                                    {
                                        DomainNumberLimit = 1;
                                    }

                                    return;
                                case 1:
                                    Trace.WriteLine("EndTime");
                                    EndTime = DateTime.FromFileTimeUtc(BitConverter.ToInt64(data, 0));
                                    break;
                                case 2:
                                    Trace.WriteLine("DomainLimitation");
                                    DomainLimitation = Encoding.Unicode.GetString(data);
                                    break;
                                case 3:
                                    Trace.WriteLine("CustomerNotice");
                                    CustomerNotice = Encoding.Unicode.GetString(data);
                                    break;
                                case 4:
                                    Trace.WriteLine("Edition");
                                    Edition = Encoding.Unicode.GetString(data);
                                    break;
                                case 5:
                                    DomainNumberLimit = BitConverter.ToInt32(data, 0);
                                    break;
                            }

                            ms2.Write(BitConverter.GetBytes(infoType), 0, 4);
                            ms2.Write(BitConverter.GetBytes(data.Length), 0, 4);
                            ms2.Write(data, 0, data.Length);
                        }
                    }
                }
            }
        }

        private void VerifyLicenseV1()
        {
            byte[] b = Convert.FromBase64String(_licKey);

            MemoryStream ms = new MemoryStream();
            ms.Write(b, 0, b.Length);
            ms.Position = 0;
            byte[] date = new byte[readint(ms)];
            byte[] limitation = new byte[readint(ms)];
            byte[] notice = new byte[readint(ms)];
            byte[] signature = new byte[readint(ms)];
            Trace.WriteLine("reading date");
            ms.Read(date, 0, date.Length);
            Trace.WriteLine("reading limitation");
            ms.Read(limitation, 0, limitation.Length);
            Trace.WriteLine("reading notice");
            ms.Read(notice, 0, notice.Length);
            Trace.WriteLine("reading signature");
            ms.Read(signature, 0, signature.Length);
            Trace.WriteLine("reading done");
            byte[] bytes = new byte[date.Length + limitation.Length + notice.Length];

            Array.Copy(date, 0, bytes, 0, date.Length);
            Array.Copy(limitation, 0, bytes, date.Length, limitation.Length);
            Array.Copy(notice, 0, bytes, limitation.Length + date.Length, notice.Length);

            VerifySignature(signature, bytes);

            EndTime = DateTime.FromFileTimeUtc(BitConverter.ToInt64(date, 0));
            Trace.WriteLine("Endtime=" + EndTime);
            DomainLimitation = Encoding.Unicode.GetString(limitation);
            Trace.WriteLine("DomainLimitation=" + DomainLimitation);
            CustomerNotice = Encoding.Unicode.GetString(notice);
            Trace.WriteLine("CustomerNotice=" + CustomerNotice);
            Trace.WriteLine("license verified");
        }

        private void VerifySignature(byte[] signature, byte[] dataToVerify)
        {
            Trace.WriteLine("hashing license info");
            using (SHA1 hashstring = SHA1.Create())
            {
                byte[] hash = hashstring.ComputeHash(dataToVerify);
                Trace.WriteLine("hashing done");
                Trace.WriteLine("loading rsa key");
                using (RSACryptoServiceProvider RSA = LoadRSAKey())
                {
                    Trace.WriteLine("loading rsa key");
                    Trace.WriteLine("verifying the signature");
                    if (!RSA.VerifyHash(hash, "1.3.14.3.2.26", signature))
                    {
                        throw new Exception("Invalid signature");
                    }

                    Trace.WriteLine("signature ok");
                }
            }
        }

        private RSACryptoServiceProvider LoadRSAKey()
        {
            RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
            RSAParameters parameters = new RSAParameters();
            parameters.Modulus = Convert.FromBase64String("wNtlwFv+zo0lrShHnSi5VLT6Sbfx3ZXhtefSJfYs3YjWyPHv3ihLjXlBjMlGI5ziXrjcriNNZ5zn2P2qvv3VdX02zsIuGuAYZi0c4WBhiqtKgTo7USxsAaGxpqiWTkW3NQylw27p3jqICO7cbLXsr3aEZJJUgqkNay/l4S3pYIs=");
            parameters.Exponent = Convert.FromBase64String("AQAB");
            RSA.ImportParameters(parameters);
            return RSA;
        }

        private int readint(Stream stream)
        {
            byte[] temp = new byte[4];
            stream.Read(temp, 0, 4);
            int size = BitConverter.ToInt32(temp, 0);
            return size;
        }

        /// <summary>
        /// Pre-compiles domain patterns for optimal performance in IsAllowedDomain.
        /// Called once after license verification.
        /// Compiles regex for each domain pattern separated by comma, semicolon, or pipe.
        /// </summary>
        private void InitializeDomainPatterns()
        {
            if (string.IsNullOrEmpty(DomainLimitation))
            {
                _compiledDomainPatterns = new List<Regex>();
                return;
            }

            var patterns = DomainLimitation.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries);
            _compiledDomainPatterns = new List<Regex>();

            foreach (var pattern in patterns)
            {
                var trimmed = pattern.Trim();
                if (!string.IsNullOrEmpty(trimmed))
                {
                    string regexPattern = "^" + Regex.Escape(trimmed)
                                                .Replace(@"\*", ".*")
                                                .Replace(@"\?", ".")
                                         + "$";
                    var compiledRegex = new Regex(regexPattern, RegexOptions.IgnoreCase | RegexOptions.Compiled);
                    _compiledDomainPatterns.Add(compiledRegex);
                }
            }
        }

        /// <summary>
        /// Disposes this object.
        /// </summary>
        public sealed override void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Disposes this object.
        /// </summary>
        /// <param name="disposing">true if the object is disposing.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (!_disposed)
                {
                    //Custom disposing here.
                }

                _disposed = true;
            }
        }

        public bool IsBasic()
        {
            if (!IsVerified)
            {
                throw new PingCastleException("License has not been verified. Call Verify() first.");
            }

            return string.Equals(Edition, "Basic", StringComparison.OrdinalIgnoreCase);
        }

        public void TraceInfo()
        {
            if (!IsVerified)
            {
                throw new PingCastleException("License has not been verified. Call Verify() first.");
            }

            Trace.WriteLine($"License checked: {IsVerified}");
            Trace.WriteLine($"CustomerNotice: {CustomerNotice}");
            Trace.WriteLine($"DomainLimitation: {DomainLimitation}");
            Trace.WriteLine($"DomainNumberLimit: {DomainNumberLimit}");
            Trace.WriteLine($"Edition: {Edition}");
            Trace.WriteLine($"EndTime: {EndTime}");
            Trace.WriteLine($"LicenseStatus: {LicenseStatus}");
        }

        public void UpdateLicenseStatus(int totalApproximateUserCount)
        {
            if (!IsVerified)
            {
                throw new PingCastleException("License has not been verified. Call Verify() first.");
            }

            if (!_licensedUserCount.HasValue || _licensedUserCount == 0)
            {
                _licenseStatus = "Normal";
                return;
            }

            if (totalApproximateUserCount > _licensedUserCount.Value)
            {
                _licenseStatus = "OverSoftLimit";
                Trace.WriteLine($"License status: OverSoftLimit (users: {totalApproximateUserCount} > licensed: {_licensedUserCount})");
            }
            else
            {
                _licenseStatus = "Normal";
                Trace.WriteLine($"License status: Normal (users: {totalApproximateUserCount} <= licensed: {_licensedUserCount})");
            }
        }

        /// <summary>
        /// Checks if a domain is allowed by this license's DomainLimitation.
        /// Only enforces for V3 licenses (starting with PC3).
        /// V2 licenses (starting with PC2) allow all domains.
        /// Optimized with pre-compiled regex patterns for maximum performance.
        /// </summary>
        /// <param name="domainToCheck">Domain name to check</param>
        /// <returns>true if domain is allowed, false if not allowed</returns>
        public bool IsAllowedDomain(string domainToCheck)
        {
            if (!IsVerified)
            {
                throw new PingCastleException("License has not been verified. Call Verify() first.");
            }

            if (_compiledDomainPatterns.Count == 0)
            {
                InitializeDomainPatterns();
            }

            if (!_isV3License || _compiledDomainPatterns.Count == 0)
            {
                return true;
            }

            foreach (var compiledPattern in _compiledDomainPatterns)
            {
                if (compiledPattern.IsMatch(domainToCheck))
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Gets the validation error message for this license's DomainLimitation field.
        /// Returns empty string if valid or null/empty, or error message if invalid.
        /// Only validates V3 licenses.
        /// </summary>
        /// <returns>Error message or empty string if valid</returns>
        public string GetDomainValidationError()
        {
            if (!IsVerified)
            {
                throw new PingCastleException("License has not been verified. Call Verify() first.");
            }

            if (String.IsNullOrEmpty(DomainLimitation))
            {
                return String.Empty;
            }

            bool isV3License = !String.IsNullOrEmpty(_licKey) && _licKey.StartsWith("PC3");

            if (!isV3License)
            {
                return String.Empty;
            }

            var patterns = DomainLimitation.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries);

            foreach (var pattern in patterns)
            {
                var trimmed = pattern.Trim();
                if (String.IsNullOrEmpty(trimmed))
                {
                    continue;
                }

                var error = ValidateSingleDomainPatternError(trimmed);
                if (!String.IsNullOrEmpty(error))
                {
                    return error;
                }
            }

            return String.Empty;
        }

        /// <summary>
        /// Gets a formatted string describing the domain limitation patterns.
        /// </summary>
        /// <returns>Formatted domain limitation string or descriptive message</returns>
        public string GetDomainLimitationPatterns()
        {
            if (!IsVerified)
            {
                throw new PingCastleException("License has not been verified. Call Verify() first.");
            }

            if (String.IsNullOrEmpty(DomainLimitation))
            {
                return "None";
            }

            bool isV3License = !String.IsNullOrEmpty(_licKey) && _licKey.StartsWith("PC3");

            if (!isV3License)
            {
                return "Not enforced (V2 License)";
            }

            return DomainLimitation;
        }

        /// <summary>
        /// Gets error message for a single invalid domain pattern.
        /// </summary>
        private static string ValidateSingleDomainPatternError(string domain)
        {
            if (domain == "*")
            {
                return "Domain name cannot be only an asterisk.";
            }

            var domainToValidate = StripWildcardPrefix(domain, out var hasWildcard);

            if (domainToValidate == null)
            {
                return String.Format("Invalid wildcard domain format: '{0}'. Expected format: *.example.com", domain);
            }

            if (String.IsNullOrEmpty(domainToValidate) || domainToValidate.Length > 253)
            {
                return String.Format("Invalid domain: '{0}'.", domain);
            }

            var labels = domainToValidate.Split('.');

            foreach (var label in labels)
            {
                if (String.IsNullOrEmpty(label))
                {
                    return String.Format("Domain '{0}' contains consecutive dots or empty labels.", domain);
                }

                if (label.Length > 63)
                {
                    return String.Format("Domain label '{0}' exceeds maximum length of 63 characters.", label);
                }

                if (!HasValidCharacters(label))
                {
                    return String.Format("Domain label '{0}' contains invalid characters.", label);
                }

                if (label[0] == '-' || label[label.Length - 1] == '-')
                {
                    return String.Format("Domain label '{0}' cannot start or end with a hyphen.", label);
                }
            }

            return String.Empty;
        }

        /// <summary>
        /// Strips wildcard prefix from domain if present.
        /// Returns null if wildcard format is invalid.
        /// </summary>
        private static string? StripWildcardPrefix(string domain, out bool hasWildcard)
        {
            hasWildcard = false;

            if (!domain.StartsWith("*"))
            {
                return domain;
            }

            hasWildcard = true;

            if (domain.Length < 3 || domain[1] != '.')
            {
                return null;
            }

            return domain.Substring(2);
        }

        /// <summary>
        /// Validates that label contains only alphanumeric characters and hyphens.
        /// </summary>
        private static bool HasValidCharacters(string label)
        {
            foreach (var c in label)
            {
                if (!char.IsLetterOrDigit(c) && c != '-')
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Compares a string with wildcard patterns (* for any characters, ? for single character).
        /// Case-insensitive matching.
        /// </summary>
        private static bool compareStringWithWildcard(string stringWithWildcard, string toCompare)
        {
            string regex = "^" + System.Text.RegularExpressions.Regex.Escape(stringWithWildcard)
                              .Replace(@"\*", ".*")
                              .Replace(@"\?", ".")
                           + "$";
            return System.Text.RegularExpressions.Regex.Match(toCompare, regex, System.Text.RegularExpressions.RegexOptions.IgnoreCase).Success;
        }
    }
}
