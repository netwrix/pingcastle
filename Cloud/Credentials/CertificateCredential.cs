//
// Copyright (c) Vincent LE TOUX for Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using Microsoft.Win32.SafeHandles;
using PingCastle.Cloud.RESTServices.Azure;
using PingCastle.Cloud.Tokens;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace PingCastle.Cloud.Credentials
{
    public class CertificateCredential : IDisposable, IAzureCredential
    {
        public bool ForceRefreshByRefreshToken { get; set; }
        private CertificateCredential()
        {

        }

        public static CertificateCredential LoadFromCertificate(string clientId, string tenantId, X509Certificate2 certificate)
        {
            if (!certificate.HasPrivateKey)
                throw new ApplicationException("Certificate without private key");

            var cred = new CertificateCredential();
            cred.PrivateKey = (RSA)certificate.PrivateKey;
            cred.ThumbPrint = certificate.Thumbprint;
            cred.ClientId = clientId;
            cred.Tenantid = tenantId;
            return cred;
        }

        public static CertificateCredential LoadFromKeyFile(string clientId, string tenantId, string key, string thumbPrint)
        {
            byte[] keyB = StringToBinary(key);
            var cred = new CertificateCredential();
            cred.PrivateKey = DecodePKCS8Blob(keyB);
            cred.ThumbPrint = thumbPrint;
            cred.ClientId = clientId;
            cred.Tenantid = tenantId;
            return cred;
        }

        public static CertificateCredential LoadFromP12(string clientId, string tenantId, string p12file, string password)
        {
            var data = File.ReadAllBytes(p12file);
            IntPtr buffer = Marshal.AllocHGlobal(data.Length);
            IntPtr handle;
            try
            {
                Marshal.Copy(data, 0, buffer, data.Length);
                var pfxBlob = new CRYPTOAPI_BLOB { cbData = data.Length, pbData = buffer };
                Trace.WriteLine("Before loading p12 " + p12file);
                handle = PFXImportCertStore(ref pfxBlob, password, CRYPT_EXPORTABLE | CRYPT_USER_KEYSET);
                if (handle == IntPtr.Zero)
                    throw new Win32Exception();
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
            var store = new X509Store(handle);
            {
                foreach (var certificate in store.Certificates)
                {
                    if (certificate.HasPrivateKey)
                    {
                        var cred = new CertificateCredential();
                        cred.PrivateKey = (RSA)certificate.PrivateKey;
                        cred.ThumbPrint = certificate.Thumbprint;
                        cred.ClientId = clientId;
                        cred.Tenantid = tenantId;
                        store.Close();
                        return cred;
                    }
                }
                store.Close();
            }
            throw new ApplicationException("No private key found in pfx file");
        }

        public async Task<Token> GetToken<T>() where T : IAzureService
        {
            return await TokenFactory.GetToken<T>(this);
        }

        public string ClientId { get; private set; }
        public string Tenantid { get; set; }
        public string TenantidToQuery { get; set; }
        public RSA PrivateKey { get; private set; }
        public string ThumbPrint { get; private set; }

        public Token LastTokenQueried { get; private set; }

        public void Dispose()
        {
            if (PrivateKey != null)
                PrivateKey.Dispose();
            PrivateKey = null;
        }

        const int CRYPT_EXPORTABLE = 1;
        const int CRYPT_USER_KEYSET = 0x1000;


        [DllImport("crypt32.dll", SetLastError = true)]
        static extern IntPtr PFXImportCertStore(ref CRYPTOAPI_BLOB pPfx, [MarshalAs(UnmanagedType.LPWStr)] String szPassword, uint dwFlags);

        enum CRYPT_STRING_FLAGS : uint
        {
            CRYPT_STRING_BASE64_ANY = 6,
        }

        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CryptStringToBinary([MarshalAs(UnmanagedType.LPWStr)] string pszString, int cchString, CRYPT_STRING_FLAGS dwFlags, [Out] IntPtr pbBinary, ref int pcbBinary, out int pdwSkip, out int pdwFlags);
        static byte[] StringToBinary(string datastr)
        {
            int flags, skipbytes, buflen;

            buflen = datastr.Length;
            IntPtr buffer = Marshal.AllocHGlobal(buflen);
            try
            {
                bool status = CryptStringToBinary(datastr,
                    datastr.Length,
                    CRYPT_STRING_FLAGS.CRYPT_STRING_BASE64_ANY,
                    buffer,
                    ref buflen,
                    out skipbytes,
                    out flags);

                if (!status)
                {
                    Trace.WriteLine("Unable to decode the private key");
                    throw new Win32Exception();
                }
                byte[] keybytes = new byte[buflen];
                Marshal.Copy(buffer, keybytes, 0, (int)buflen);
                return keybytes;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        const int X509_ASN_ENCODING = 0x00000001;
        const int PKCS_7_ASN_ENCODING = 0x00010000;

        sealed class LocalAllocHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            private LocalAllocHandle() : base(ownsHandle: true) { }

            public static LocalAllocHandle Alloc(int cb)
            {
                LocalAllocHandle handle = new LocalAllocHandle();
                handle.AllocCore(cb);
                return handle;
            }

            [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
            private void AllocCore(int cb)
            {
                SetHandle(Marshal.AllocHGlobal(cb));
            }

            protected override bool ReleaseHandle()
            {
                Marshal.FreeHGlobal(handle);
                return true;
            }
        }


        [DllImport("crypt32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CryptDecodeObjectEx(
            uint dwCertEncodingType,
            uint lpszStructType,
            IntPtr pbEncoded,
            int cbEncoded,
            uint dwFlags,
            IntPtr pDecodePara,
            out LocalAllocHandle pvStructInfo,
            out uint pcbStructInfo);

        const uint CNG_RSA_PRIVATE_KEY_BLOB = 83;
        const uint PKCS_PRIVATE_KEY_INFO = 44;
        const uint CRYPT_DECODE_ALLOC_FLAG = 0x8000;

        [StructLayout(LayoutKind.Sequential)]
        struct CRYPT_ALGORITHM_IDENTIFIER
        {
            [MarshalAs(UnmanagedType.LPStr)]
            public string pszObjId;
            CRYPTOAPI_BLOB Parameters;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct CRYPTOAPI_BLOB
        {
            public int cbData;
            public IntPtr pbData;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct CRYPT_PRIVATE_KEY_INFO
        {
            public int Version;
            public CRYPT_ALGORITHM_IDENTIFIER Algorithm;
            public CRYPTOAPI_BLOB PrivateKey;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct BCRYPT_RSAKEY_BLOB
        {
            public int Magic;
            public int BitLength;
            public int cbPublicExp;
            public int cbModulus;
            public int cbPrime1;
            public int cbPrime2;
        }

        static RSA DecodePKCS8Blob(byte[] derBlob)
        {
            using (var derBlobHandle = LocalAllocHandle.Alloc(derBlob.Length))
            {
                Marshal.Copy(
                    derBlob,
                    0,
                    derBlobHandle.DangerousGetHandle(),
                    derBlob.Length);

                //
                // Decode RSA PublicKey DER -> CSP blob.
                //
                LocalAllocHandle keyBlobHandle;
                uint keyBlobSize;
                if (CryptDecodeObjectEx(
                    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                    PKCS_PRIVATE_KEY_INFO,
                    derBlobHandle.DangerousGetHandle(),
                    derBlob.Length,
                    CRYPT_DECODE_ALLOC_FLAG,
                    IntPtr.Zero,
                    out keyBlobHandle,
                    out keyBlobSize))
                {
                    var keyInfo = (CRYPT_PRIVATE_KEY_INFO)Marshal.PtrToStructure(keyBlobHandle.DangerousGetHandle(), typeof(CRYPT_PRIVATE_KEY_INFO));
                    byte[] data = new byte[keyInfo.PrivateKey.cbData];
                    Marshal.Copy(keyInfo.PrivateKey.pbData, data, 0, keyInfo.PrivateKey.cbData);

                    var h = LocalAllocHandle.Alloc(keyInfo.PrivateKey.cbData);
                    Marshal.Copy(data, 0, h.DangerousGetHandle(), keyInfo.PrivateKey.cbData);

                    return PKCS8BlobToCNG(h, keyInfo.PrivateKey.cbData);
                }
                else
                {
                    throw new CryptographicException(
                        "Failed to decode DER blob",
                        new Win32Exception());
                }
            }
        }

        static RSA PKCS8BlobToCNG(LocalAllocHandle BlobHandle, int BlobSize)
        {

            //
            // Decode RSA PublicKey DER -> CSP blob.
            //
            LocalAllocHandle keyBlobHandle;
            uint keyBlobSize;
            if (CryptDecodeObjectEx(
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                CNG_RSA_PRIVATE_KEY_BLOB,
                BlobHandle.DangerousGetHandle(),
                BlobSize,
                CRYPT_DECODE_ALLOC_FLAG,
                IntPtr.Zero,
                out keyBlobHandle,
                out keyBlobSize))
            {
                return BlobToRSA(keyBlobHandle);
            }
            else
            {
                throw new CryptographicException(
                    "Failed to decode DER blob",
                    new Win32Exception());
            }
        }

        static byte[] ReadData(IntPtr data, int offset, int size)
        {
            byte[] managedArray = new byte[size];
            Marshal.Copy(new IntPtr(data.ToInt64() + offset), managedArray, 0, size);
            return managedArray;
        }
        static RSA BlobToRSA(LocalAllocHandle keyBlobHandle)
        {
            IntPtr data = keyBlobHandle.DangerousGetHandle();
            var blob = (BCRYPT_RSAKEY_BLOB)Marshal.PtrToStructure(data, typeof(BCRYPT_RSAKEY_BLOB));

            // https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob
            var param = new RSAParameters();
            if (blob.Magic != 0x32415352 && blob.Magic != 0x33415352)
            {
                throw new ApplicationException("Invalid blob");
            }
            int offset = Marshal.SizeOf(blob);
            param.Exponent = ReadData(data, offset, blob.cbPublicExp);
            offset += blob.cbPublicExp;
            param.Modulus = ReadData(data, offset, blob.cbModulus);
            offset += blob.cbModulus;
            param.P = ReadData(data, offset, blob.cbPrime1);
            offset += blob.cbPrime1;
            param.Q = ReadData(data, offset, blob.cbPrime2);
            offset += blob.cbPrime2;
            /*if (blob.Magic == 0x33415352)
            {
            }*/

            var output = RSA.Create();
            output.ImportParameters(param);
            return output;
        }
    }
}

