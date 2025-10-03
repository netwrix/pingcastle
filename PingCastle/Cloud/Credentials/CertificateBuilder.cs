using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace PingCastle.Cloud.Credentials
{
    class CertificateBuilder
    {
        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern IntPtr CertCreateSelfSignCertificate(
            IntPtr hCryptProvOrNCryptKey,
            ref CryptoApiBlob pSubjectIssuerBlob,
            int dwFlags,
            ref CryptKeyProvInfo pKeyProvInfo,
            ref AlgorithmIdentifier pSignatureAlgorithm,
            ref SYSTEMTIME pStartTime,
            ref SYSTEMTIME pEndTime,
            IntPtr pExtensions
        );

        [DllImport("crypt32.dll", SetLastError = true)]
        static extern bool CertStrToName(
                uint dwCertEncodingType,
                string pszX500,
                uint dwStrType,
                IntPtr pvReserved,
                byte[] pbEncoded,
                ref uint pcbEncoded,
                StringBuilder ppszError
            );

        [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern IntPtr CertOpenStore(int storeProvider, int encodingType,
           IntPtr hcryptProv, int flags, IntPtr pvPara);

        struct CryptoApiBlob
        {
            public Int32 cbData;
            public IntPtr pbData;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct CryptKeyProvInfo
        {
            public IntPtr pwszContainerName;
            public IntPtr pwszProvName;
            public int dwProvType;
            public int dwFlags;
            public int cProvParam;
            public IntPtr rgProvParam;
            public int dwKeySpec;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SYSTEMTIME
        {
            [MarshalAs(UnmanagedType.U2)]
            public short Year;
            [MarshalAs(UnmanagedType.U2)]
            public short Month;
            [MarshalAs(UnmanagedType.U2)]
            public short DayOfWeek;
            [MarshalAs(UnmanagedType.U2)]
            public short Day;
            [MarshalAs(UnmanagedType.U2)]
            public short Hour;
            [MarshalAs(UnmanagedType.U2)]
            public short Minute;
            [MarshalAs(UnmanagedType.U2)]
            public short Second;
            [MarshalAs(UnmanagedType.U2)]
            public short Milliseconds;

            public SYSTEMTIME(DateTime dt)
            {
                dt = dt.ToUniversalTime();  // SetSystemTime expects the SYSTEMTIME in UTC
                Year = (short)dt.Year;
                Month = (short)dt.Month;
                DayOfWeek = (short)dt.DayOfWeek;
                Day = (short)dt.Day;
                Hour = (short)dt.Hour;
                Minute = (short)dt.Minute;
                Second = (short)dt.Second;
                Milliseconds = (short)dt.Millisecond;
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        struct AlgorithmIdentifier
        {
            public string ObjectId;
            public CryptoApiBlob Parameters;
        }

        const Int32 X509_ASN_ENCODING = 0x00000001;
        const Int32 CERT_X500_NAME_STR = 0x00000003;

        static public void GenerateAzureADCertificate(string tenant, string password, DateTime expirationDate)
        {
            RSACryptoServiceProvider RSA = new RSACryptoServiceProvider(2048, new CspParameters { KeyContainerName = Guid.NewGuid().ToString() });
            try
            {
                var cert = CreateSelfSignedCertificate(RSA, tenant, expirationDate);
                SaveCert(cert, "PSCC-" + tenant + "-App.cer");
                SaveP12(RSA, cert, "PSCC-" + tenant + "-App.p12", password);
            }
            finally
            {
                RSA.Clear();
            }
        }

        static X509Certificate2 CreateSelfSignedCertificate(RSACryptoServiceProvider RSA, string dnsname, DateTime expirationDate)
        {
            var expire = new SYSTEMTIME(expirationDate);
            var start = new SYSTEMTIME(DateTime.Now);
            var signature = new AlgorithmIdentifier();
            signature.ObjectId = "1.2.840.113549.1.1.11";
            var subject = new CryptoApiBlob();
            var s = Encode("CN=" + dnsname);
            subject.pbData = Marshal.AllocHGlobal(s.Length);

            var info = RSA.CspKeyContainerInfo;
            var cn = Marshal.StringToHGlobalUni(info.KeyContainerName);
            var pn = Marshal.StringToHGlobalUni(info.ProviderName);

            try
            {
                Marshal.Copy(s, 0, subject.pbData, s.Length);
                subject.cbData = s.Length;

                CryptKeyProvInfo provInfo = new CryptKeyProvInfo
                {
                    dwKeySpec = 1,
                    dwProvType = info.ProviderType,
                    pwszContainerName = cn,
                    pwszProvName = pn,
                };

                var pccert_context = CertCreateSelfSignCertificate(IntPtr.Zero, ref subject, 0, ref provInfo, ref signature, ref start, ref expire, IntPtr.Zero);
                if (pccert_context == IntPtr.Zero)
                {
                    throw new CryptographicException(Marshal.GetLastWin32Error());
                }
                return new X509Certificate2(pccert_context);

            }
            finally
            {
                Marshal.FreeHGlobal(subject.pbData);
                Marshal.FreeHGlobal(cn);
                Marshal.FreeHGlobal(pn);
            }
        }

        static void SaveCert(X509Certificate2 cert, string filename)
        {
            var data = cert.GetRawCertData();
            File.WriteAllBytes(filename, data);
        }

        static void SaveP12(RSACryptoServiceProvider RSA, X509Certificate2 cert, string filename, string password)
        {
            var data = cert.Export(X509ContentType.Pkcs12, password);
            File.WriteAllBytes(filename, data);
        }

        static byte[] Encode(string data)
        {
            
            uint cbEncoded = 0;
            byte[] bData;
            if (!CertStrToName(X509_ASN_ENCODING, data, CERT_X500_NAME_STR, IntPtr.Zero, null, ref cbEncoded, null))
            {
                throw new CryptographicException(Marshal.GetLastWin32Error());
            }
            bData = new byte[cbEncoded];
            if (!CertStrToName(X509_ASN_ENCODING, data, CERT_X500_NAME_STR, IntPtr.Zero, bData, ref cbEncoded, null))
            {
                throw new CryptographicException(Marshal.GetLastWin32Error());
            }

            return (bData);
        }

    }
}
