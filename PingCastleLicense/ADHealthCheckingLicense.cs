//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.ComponentModel;
using System.Configuration;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

namespace PingCastle
{
    public class ADHealthCheckingLicense : License, IDisposable
    {
        private bool _disposed = false;
        private string _licKey = null;
        private string edition;

        public ADHealthCheckingLicense(string license)
            : this(license, true)
        {

        }

        public ADHealthCheckingLicense(string license, bool DoAKeyCheck)
        {
            if (String.IsNullOrEmpty(license))
                throw new PingCastleException("No PingCastle license has been provided");
            _licKey = license;
            Trace.WriteLine("License: " + _licKey);
            if (!VerifyKey())
            {
                throw new PingCastleException("The PingCastle license is not valid");
            }
        }

        #region Properties

        public DateTime EndTime { get; set; }
        public string DomainLimitation { get; set; }
        public string CustomerNotice { get; set; }
        public string Edition
        {
            get
            {
                return string.IsNullOrEmpty(edition) ? "Basic" : edition;
            }
            set
            {
                edition = value;
            }
        }
        public int? DomainNumberLimit { get; set; }

        /// <summary>
        /// Gets the license key granted to this component.
        /// </summary>
        public override string LicenseKey
        {
            get { return _licKey; }
        }

        #endregion

        private bool VerifyKey()
        {
#if DEBUG
            if (_licKey.Equals("debug", StringComparison.InvariantCultureIgnoreCase))
            {
                EndTime = DateTime.MaxValue;
                DomainLimitation = null;
                CustomerNotice = "debug version";
                return true;
            }
#endif
            try
            {
                Trace.WriteLine("starting the license analysis");

                Trace.WriteLine("License info uncompressed");
                if (_licKey != null && _licKey.StartsWith("PC2"))
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
                                        DomainNumberLimit = 1;
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

        int readint(Stream stream)
        {
            byte[] temp = new byte[4];
            stream.Read(temp, 0, 4);
            int size = BitConverter.ToInt32(temp, 0);
            return size;
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
            return string.Equals(Edition, "Basic", StringComparison.OrdinalIgnoreCase);
        }

    }
}
