using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace PingCastle.RPC
{
    using System.Net;

    public enum SecBufferType
    {
        SECBUFFER_VERSION = 0,
        SECBUFFER_EMPTY = 0,
        SECBUFFER_DATA = 1,
        SECBUFFER_TOKEN = 2
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SecHandle //=PCtxtHandle
    {
        IntPtr dwLower; // ULONG_PTR translates to IntPtr not to uint
        IntPtr dwUpper; // this is crucial for 64-Bit Platforms
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SecBuffer : IDisposable
    {
        public int cbBuffer;
        public int BufferType;
        public IntPtr pvBuffer;


        public SecBuffer(int bufferSize)
        {
            cbBuffer = bufferSize;
            BufferType = (int)SecBufferType.SECBUFFER_TOKEN;
            pvBuffer = Marshal.AllocHGlobal(bufferSize);
        }

        public SecBuffer(byte[] secBufferBytes)
        {
            cbBuffer = secBufferBytes.Length;
            BufferType = (int)SecBufferType.SECBUFFER_TOKEN;
            pvBuffer = Marshal.AllocHGlobal(cbBuffer);
            Marshal.Copy(secBufferBytes, 0, pvBuffer, cbBuffer);
        }

        public SecBuffer(byte[] secBufferBytes, SecBufferType bufferType)
        {
            cbBuffer = secBufferBytes.Length;
            BufferType = (int)bufferType;
            pvBuffer = Marshal.AllocHGlobal(cbBuffer);
            Marshal.Copy(secBufferBytes, 0, pvBuffer, cbBuffer);
        }

        public void Dispose()
        {
            if (pvBuffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(pvBuffer);
                pvBuffer = IntPtr.Zero;
            }
        }
    }

    public struct MultipleSecBufferHelper
    {
        public byte[] Buffer;
        public SecBufferType BufferType;

        public MultipleSecBufferHelper(byte[] buffer, SecBufferType bufferType)
        {
            if (buffer == null || buffer.Length == 0)
            {
                throw new ArgumentException("buffer cannot be null or 0 length");
            }

            Buffer = buffer;
            BufferType = bufferType;
        }
    };

    [StructLayout(LayoutKind.Sequential)]
    public struct SecBufferDesc : IDisposable
    {

        public int ulVersion;
        public int cBuffers;
        public IntPtr pBuffers; //Point to SecBuffer

        public SecBufferDesc(int bufferSize)
        {
            ulVersion = (int)SecBufferType.SECBUFFER_VERSION;
            cBuffers = 1;
            SecBuffer ThisSecBuffer = new SecBuffer(bufferSize);
            pBuffers = Marshal.AllocHGlobal(Marshal.SizeOf(ThisSecBuffer));
            Marshal.StructureToPtr(ThisSecBuffer, pBuffers, false);
        }

        public SecBufferDesc(byte[] secBufferBytes)
        {
            ulVersion = (int)SecBufferType.SECBUFFER_VERSION;
            cBuffers = 1;
            SecBuffer ThisSecBuffer = new SecBuffer(secBufferBytes);
            pBuffers = Marshal.AllocHGlobal(Marshal.SizeOf(ThisSecBuffer));
            Marshal.StructureToPtr(ThisSecBuffer, pBuffers, false);
        }

        public SecBufferDesc(MultipleSecBufferHelper[] secBufferBytesArray)
        {
            if (secBufferBytesArray == null || secBufferBytesArray.Length == 0)
            {
                throw new ArgumentException("secBufferBytesArray cannot be null or 0 length");
            }

            ulVersion = (int)SecBufferType.SECBUFFER_VERSION;
            cBuffers = secBufferBytesArray.Length;

            //Allocate memory for SecBuffer Array....
            pBuffers = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SecBuffer)) * cBuffers);

            for (int Index = 0; Index < secBufferBytesArray.Length; Index++)
            {
                //Super hack: Now allocate memory for the individual SecBuffers
                //and just copy the bit values to the SecBuffer array!!!
                SecBuffer ThisSecBuffer = new SecBuffer(secBufferBytesArray[Index].Buffer, secBufferBytesArray[Index].BufferType);

                //We will write out bits in the following order:
                //int cbBuffer;
                //int BufferType;
                //pvBuffer;
                //Note that we won't be releasing the memory allocated by ThisSecBuffer until we
                //are disposed...
                int CurrentOffset = Index * Marshal.SizeOf(typeof(SecBuffer));
                Marshal.WriteInt32(pBuffers, CurrentOffset, ThisSecBuffer.cbBuffer);
                Marshal.WriteInt32(pBuffers, CurrentOffset + Marshal.SizeOf(ThisSecBuffer.cbBuffer), ThisSecBuffer.BufferType);
                Marshal.WriteIntPtr(pBuffers, CurrentOffset + Marshal.SizeOf(ThisSecBuffer.cbBuffer) + Marshal.SizeOf(ThisSecBuffer.BufferType), ThisSecBuffer.pvBuffer);
            }
        }

        public void Dispose()
        {
            if (pBuffers != IntPtr.Zero)
            {
                if (cBuffers == 1)
                {
                    SecBuffer ThisSecBuffer = (SecBuffer)Marshal.PtrToStructure(pBuffers, typeof(SecBuffer));
                    ThisSecBuffer.Dispose();
                }
                else
                {
                    for (int Index = 0; Index < cBuffers; Index++)
                    {
                        //The bits were written out the following order:
                        //int cbBuffer;
                        //int BufferType;
                        //pvBuffer;
                        //What we need to do here is to grab a hold of the pvBuffer allocate by the individual
                        //SecBuffer and release it...
                        int CurrentOffset = Index * Marshal.SizeOf(typeof(SecBuffer));
                        IntPtr SecBufferpvBuffer = Marshal.ReadIntPtr(pBuffers, CurrentOffset + Marshal.SizeOf(typeof(int)) + Marshal.SizeOf(typeof(int)));
                        Marshal.FreeHGlobal(SecBufferpvBuffer);
                    }
                }

                Marshal.FreeHGlobal(pBuffers);
                pBuffers = IntPtr.Zero;
            }
        }

        public byte[] GetSecBufferByteArray()
        {
            byte[] Buffer = null;

            if (pBuffers == IntPtr.Zero)
            {
                throw new InvalidOperationException("Object has already been disposed!!!");
            }

            if (cBuffers == 1)
            {
                SecBuffer ThisSecBuffer = (SecBuffer)Marshal.PtrToStructure(pBuffers, typeof(SecBuffer));

                if (ThisSecBuffer.cbBuffer > 0)
                {
                    Buffer = new byte[ThisSecBuffer.cbBuffer];
                    Marshal.Copy(ThisSecBuffer.pvBuffer, Buffer, 0, ThisSecBuffer.cbBuffer);
                }
            }
            else
            {
                int BytesToAllocate = 0;

                for (int Index = 0; Index < cBuffers; Index++)
                {
                    //The bits were written out the following order:
                    //int cbBuffer;
                    //int BufferType;
                    //pvBuffer;
                    //What we need to do here calculate the total number of bytes we need to copy...
                    int CurrentOffset = Index * Marshal.SizeOf(typeof(SecBuffer));
                    BytesToAllocate += Marshal.ReadInt32(pBuffers, CurrentOffset);
                }

                Buffer = new byte[BytesToAllocate];

                for (int Index = 0, BufferIndex = 0; Index < cBuffers; Index++)
                {
                    //The bits were written out the following order:
                    //int cbBuffer;
                    //int BufferType;
                    //pvBuffer;
                    //Now iterate over the individual buffers and put them together into a
                    //byte array...
                    int CurrentOffset = Index * Marshal.SizeOf(typeof(SecBuffer));
                    int BytesToCopy = Marshal.ReadInt32(pBuffers, CurrentOffset);
                    IntPtr SecBufferpvBuffer = Marshal.ReadIntPtr(pBuffers, CurrentOffset + Marshal.SizeOf(typeof(int)) + Marshal.SizeOf(typeof(int)));
                    Marshal.Copy(SecBufferpvBuffer, Buffer, BufferIndex, BytesToCopy);
                    BufferIndex += BytesToCopy;
                }
            }

            return (Buffer);
        }
    }


    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_INTEGER
    {
        public uint LowPart;
        public int HighPart;
        public SECURITY_INTEGER(int dummy)
        {
            LowPart = 0;
            HighPart = 0;
        }
    };

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_HANDLE
    {
        public IntPtr LowPart;
        public IntPtr HighPart;
        public SECURITY_HANDLE(int dummy)
        {
            LowPart = HighPart = IntPtr.Zero;
        }
    };

    [StructLayout(LayoutKind.Sequential)]
    public struct SecPkgContext_Sizes
    {
        public uint cbMaxToken;
        public uint cbMaxSignature;
        public uint cbBlockSize;
        public uint cbSecurityTrailer;
    };

    [StructLayout(LayoutKind.Sequential)]
    public struct SecPkgContext_SessionKey
    {
        public uint SessionKeyLength;
        public IntPtr Sessionkey;
    };

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SEC_WINNT_AUTH_IDENTITY
    {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string User;
        public int UserLength;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string Domain;
        public int DomainLength;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string Password;
        public int PasswordLength;
        public int Flags;
    };

    public class SSPIHelper
    {
        public const int TOKEN_QUERY = 0x00008;
        public const int SEC_E_OK = 0;
        public const int SEC_I_CONTINUE_NEEDED = 0x90312;
        const int SECPKG_CRED_OUTBOUND = 2;
        const int SECURITY_NATIVE_DREP = 0x10;
        const int SECPKG_CRED_INBOUND = 1;
        const int MAX_TOKEN_SIZE = 12288;
        //For AcquireCredentialsHandle in 3er Parameter "fCredentialUse"

        SECURITY_HANDLE _hCred = new SECURITY_HANDLE(0);
        public SECURITY_HANDLE _hContext = new SECURITY_HANDLE(0);

        public const int ISC_REQ_DELEGATE = 0x00000001;
        public const int ISC_REQ_MUTUAL_AUTH = 0x00000002;
        public const int ISC_REQ_REPLAY_DETECT = 0x00000004;
        public const int ISC_REQ_SEQUENCE_DETECT = 0x00000008;
        public const int ISC_REQ_CONFIDENTIALITY = 0x00000010;
        public const int ISC_REQ_USE_SESSION_KEY = 0x00000020;
        public const int ISC_REQ_PROMPT_FOR_CREDS = 0x00000040;
        public const int ISC_REQ_USE_SUPPLIED_CREDS = 0x00000080;
        public const int ISC_REQ_ALLOCATE_MEMORY = 0x00000100;
        public const int ISC_REQ_USE_DCE_STYLE = 0x00000200;
        public const int ISC_REQ_DATAGRAM = 0x00000400;
        public const int ISC_REQ_CONNECTION = 0x00000800;
        public const int ISC_REQ_CALL_LEVEL = 0x00001000;
        public const int ISC_REQ_FRAGMENT_SUPPLIED = 0x00002000;
        public const int ISC_REQ_EXTENDED_ERROR = 0x00004000;
        public const int ISC_REQ_STREAM = 0x00008000;
        public const int ISC_REQ_INTEGRITY = 0x00010000;
        public const int ISC_REQ_IDENTIFY = 0x00020000;
        public const int ISC_REQ_NULL_SESSION = 0x00040000;
        public const int ISC_REQ_MANUAL_CRED_VALIDATION = 0x00080000;
        public const int ISC_REQ_RESERVED1 = 0x00100000;
        public const int ISC_REQ_FRAGMENT_TO_FIT = 0x00200000;

        public const int SECPKG_ATTR_SIZES = 0;
        public const int SECPKG_ATTR_SESSION_KEY = 9;

        public const int STANDARD_CONTEXT_ATTRIBUTES = ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_CONNECTION;

        bool _bGotCredentials = false;

        [DllImport("secur32", CharSet = CharSet.Auto)]
        static extern int AcquireCredentialsHandle(
        string pszPrincipal, //SEC_CHAR*
        string pszPackage, //SEC_CHAR* //"Kerberos","NTLM","Negotiative"
        int fCredentialUse,
        IntPtr PAuthenticationID,//_LUID AuthenticationID,//pvLogonID, //PLUID
        IntPtr pAuthData,//PVOID
        int pGetKeyFn, //SEC_GET_KEY_FN
        IntPtr pvGetKeyArgument, //PVOID
        ref SECURITY_HANDLE phCredential, //SecHandle //PCtxtHandle ref
        ref SECURITY_INTEGER ptsExpiry); //PTimeStamp //TimeStamp ref

        [DllImport("secur32", CharSet = CharSet.Auto)]
        static extern int AcquireCredentialsHandle(
        string pszPrincipal, //SEC_CHAR*
        string pszPackage, //SEC_CHAR* //"Kerberos","NTLM","Negotiative"
        int fCredentialUse,
        IntPtr PAuthenticationID,//_LUID AuthenticationID,//pvLogonID, //PLUID
        ref SEC_WINNT_AUTH_IDENTITY pAuthData,//PVOID
        int pGetKeyFn, //SEC_GET_KEY_FN
        IntPtr pvGetKeyArgument, //PVOID
        ref SECURITY_HANDLE phCredential, //SecHandle //PCtxtHandle ref
        ref SECURITY_INTEGER ptsExpiry); //PTimeStamp //TimeStamp ref

        [DllImport("secur32", CharSet = CharSet.Auto, SetLastError = true)]
        static extern int InitializeSecurityContext(ref SECURITY_HANDLE phCredential,//PCredHandle
        IntPtr phContext, //PCtxtHandle
        string pszTargetName,
        int fContextReq,
        int Reserved1,
        int TargetDataRep,
        IntPtr pInput, //PSecBufferDesc SecBufferDesc
        int Reserved2,
        out SECURITY_HANDLE phNewContext, //PCtxtHandle
        out SecBufferDesc pOutput, //PSecBufferDesc SecBufferDesc
        out uint pfContextAttr, //managed ulong == 64 bits!!!
        out SECURITY_INTEGER ptsExpiry); //PTimeStamp

        [DllImport("secur32", CharSet = CharSet.Auto, SetLastError = true)]
        static extern int InitializeSecurityContext(ref SECURITY_HANDLE phCredential,//PCredHandle
            ref SECURITY_HANDLE phContext, //PCtxtHandle
            string pszTargetName,
            int fContextReq,
            int Reserved1,
            int TargetDataRep,
            ref SecBufferDesc SecBufferDesc, //PSecBufferDesc SecBufferDesc
            int Reserved2,
            out SECURITY_HANDLE phNewContext, //PCtxtHandle
            out SecBufferDesc pOutput, //PSecBufferDesc SecBufferDesc
            out uint pfContextAttr, //managed ulong == 64 bits!!!
            out SECURITY_INTEGER ptsExpiry); //PTimeStamp

        [DllImport("secur32.Dll", CharSet = CharSet.Auto, SetLastError = false)]
        static extern int AcceptSecurityContext(ref SECURITY_HANDLE phCredential,
                                                IntPtr phContext,
                                                ref SecBufferDesc pInput,
                                                uint fContextReq,
                                                uint TargetDataRep,
                                                out SECURITY_HANDLE phNewContext,
                                                out SecBufferDesc pOutput,
                                                out uint pfContextAttr,    //managed ulong == 64 bits!!!
                                                out SECURITY_INTEGER ptsTimeStamp);

        [DllImport("secur32.Dll", CharSet = CharSet.Auto, SetLastError = false)]
        static extern int AcceptSecurityContext(ref SECURITY_HANDLE phCredential,
                                                ref SECURITY_HANDLE phContext,
                                                ref SecBufferDesc pInput,
                                                uint fContextReq,
                                                uint TargetDataRep,
                                                out SECURITY_HANDLE phNewContext,
                                                out SecBufferDesc pOutput,
                                                out uint pfContextAttr,    //managed ulong == 64 bits!!!
                                                out SECURITY_INTEGER ptsTimeStamp);

        [DllImport("secur32.Dll", CharSet = CharSet.Auto, SetLastError = false)]
        public static extern int ImpersonateSecurityContext(ref SECURITY_HANDLE phContext);

        [DllImport("secur32.Dll", CharSet = CharSet.Auto, SetLastError = false)]
        public static extern int QueryContextAttributes(ref SECURITY_HANDLE phContext,
                                                        uint ulAttribute,
                                                        out SecPkgContext_Sizes pContextAttributes);

        [DllImport("secur32.Dll", CharSet = CharSet.Auto, SetLastError = false)]
        public static extern int QueryContextAttributes(ref SECURITY_HANDLE phContext,
                                                        uint ulAttribute,
                                                        out SecPkgContext_SessionKey pContextAttributes);

        [DllImport("secur32.Dll", CharSet = CharSet.Auto, SetLastError = false)]
        public static extern int EncryptMessage(ref SECURITY_HANDLE phContext,
                                                uint fQOP,        //managed ulong == 64 bits!!!
                                                ref SecBufferDesc pMessage,
                                                uint MessageSeqNo);    //managed ulong == 64 bits!!!

        [DllImport("secur32.Dll", CharSet = CharSet.Auto, SetLastError = false)]
        public static extern int DecryptMessage(ref SECURITY_HANDLE phContext,
                                                    ref SecBufferDesc pMessage,
                                                    uint MessageSeqNo,
                                                    out uint pfQOP);

        [DllImport("secur32.Dll", CharSet = CharSet.Auto, SetLastError = false)]
        public static extern int MakeSignature(ref SECURITY_HANDLE phContext,          // Context to use
                                                uint fQOP,         // Quality of Protection
                                                ref SecBufferDesc pMessage,        // Message to sign
                                                uint MessageSeqNo);      // Message Sequence Num.

        [DllImport("secur32.Dll", CharSet = CharSet.Auto, SetLastError = false)]
        public static extern int VerifySignature(ref SECURITY_HANDLE phContext,          // Context to use
                                                ref SecBufferDesc pMessage,        // Message to sign
                                                uint MessageSeqNo,            // Message Sequence Num.
                                                out uint pfQOP);      // Quality of Protection

        string _szTarget = WindowsIdentity.GetCurrent().Name;
        public string SecurityPackage { get; set; }

        public SSPIHelper()
        {
            SecurityPackage = "Negotiate";
        }

        public SSPIHelper(string sRemotePrincipal) : this()
        {
            _szTarget = sRemotePrincipal;
        }

        public void LoginClient(NetworkCredential login)
        {
            int ss = -1;
            SECURITY_INTEGER ClientLifeTime = new SECURITY_INTEGER(0);
            SEC_WINNT_AUTH_IDENTITY auth = new SEC_WINNT_AUTH_IDENTITY();
            auth.Domain = login.Domain;
            auth.DomainLength = login.Domain.Length;
            auth.User = login.UserName;
            auth.UserLength = login.UserName.Length;
            auth.Password = login.Password;
            auth.PasswordLength = login.Password.Length;
            auth.Flags = 2; // unicode

            ss = AcquireCredentialsHandle(_szTarget, SecurityPackage, SECPKG_CRED_OUTBOUND,
                                            IntPtr.Zero, ref auth, 0, IntPtr.Zero,
                                            ref _hCred, ref ClientLifeTime);
            if (ss != SEC_E_OK)
            {
                throw new Exception("Couldn't acquire client credentials", new Win32Exception(ss));
            }

            _bGotCredentials = true;
        }

        public void InitializeClient(out byte[] clientToken, byte[] serverToken,
                                        out bool bContinueProcessing)
        {
            clientToken = null;
            bContinueProcessing = true;
            int ss = -1;

            SECURITY_INTEGER ClientLifeTime = new SECURITY_INTEGER(0);

            if (!_bGotCredentials)
            {
                ss = AcquireCredentialsHandle(_szTarget, SecurityPackage, SECPKG_CRED_OUTBOUND,
                                            IntPtr.Zero, IntPtr.Zero, 0, IntPtr.Zero,
                                            ref _hCred, ref ClientLifeTime);
                if (ss != SEC_E_OK)
                {
                    throw new Exception("Couldn't acquire client credentials", new Win32Exception(ss));
                }

                _bGotCredentials = true;
            }



            SecBufferDesc ClientToken = new SecBufferDesc(MAX_TOKEN_SIZE);

            try
            {
                uint ContextAttributes = 0;

                if (serverToken == null)
                {
                    ss = InitializeSecurityContext(ref _hCred,
                        IntPtr.Zero,
                        _szTarget,// null string pszTargetName,
                        STANDARD_CONTEXT_ATTRIBUTES,
                        0,//int Reserved1,
                        SECURITY_NATIVE_DREP,//int TargetDataRep
                        IntPtr.Zero,    //Always zero first time around...
                        0, //int Reserved2,
                        out _hContext, //pHandle CtxtHandle = SecHandle
                        out ClientToken,//ref SecBufferDesc pOutput, //PSecBufferDesc
                        out ContextAttributes,//ref int pfContextAttr,
                        out ClientLifeTime); //ref IntPtr ptsExpiry ); //PTimeStamp

                }
                else
                {
                    SecBufferDesc ServerToken = new SecBufferDesc(serverToken);

                    try
                    {
                        ss = InitializeSecurityContext(ref _hCred,
                            ref _hContext,
                            _szTarget,// null string pszTargetName,
                            STANDARD_CONTEXT_ATTRIBUTES,
                            0,//int Reserved1,
                            SECURITY_NATIVE_DREP,//int TargetDataRep
                            ref ServerToken,    //Always zero first time around...
                            0, //int Reserved2,
                            out _hContext, //pHandle CtxtHandle = SecHandle
                            out ClientToken,//ref SecBufferDesc pOutput, //PSecBufferDesc
                            out ContextAttributes,//ref int pfContextAttr,
                            out ClientLifeTime); //ref IntPtr ptsExpiry ); //PTimeStamp
                    }
                    finally
                    {
                        ServerToken.Dispose();
                    }
                }

                if (ss != SEC_E_OK && ss != SEC_I_CONTINUE_NEEDED)
                {
                    throw new Exception("InitializeSecurityContext() failed!!!", new Win32Exception(ss));
                }

                clientToken = ClientToken.GetSecBufferByteArray();
            }
            finally
            {
                ClientToken.Dispose();
            }

            bContinueProcessing = ss != SEC_E_OK;
        }

        public void InitializeServer(byte[] clientToken, out byte[] serverToken,
                                        out bool bContinueProcessing)
        {
            serverToken = null;
            bContinueProcessing = true;
            SECURITY_INTEGER NewLifeTime = new SECURITY_INTEGER(0);
            int ss = -1;

            if (!_bGotCredentials)
            {
                ss = AcquireCredentialsHandle(_szTarget, SecurityPackage, SECPKG_CRED_INBOUND,
                                            IntPtr.Zero, IntPtr.Zero, 0, IntPtr.Zero,
                                            ref _hCred, ref NewLifeTime);
                if (ss != SEC_E_OK)
                {
                    throw new Exception("Couldn't acquire server credentials", new Win32Exception(ss));
                }

                _bGotCredentials = true;
            }

            SecBufferDesc ServerToken = new SecBufferDesc(MAX_TOKEN_SIZE);
            SecBufferDesc ClientToken = new SecBufferDesc(clientToken);

            try
            {
                uint uNewContextAttr = 0;

                if (_hContext.HighPart == _hContext.LowPart && _hContext.LowPart == IntPtr.Zero)
                {
                    ss = AcceptSecurityContext(ref _hCred,        // [in] handle to the credentials
                        IntPtr.Zero,                // [in/out] handle of partially formed context.  Always NULL the first time through
                        ref ClientToken,            // [in] pointer to the input buffers
                        STANDARD_CONTEXT_ATTRIBUTES,                        // [in] required context attributes
                        SECURITY_NATIVE_DREP,    // [in] data representation on the target
                        out _hContext,    // [in/out] receives the new context handle    
                        out ServerToken,        // [in/out] pointer to the output buffers
                        out uNewContextAttr,    // [out] receives the context attributes        
                        out NewLifeTime);        // [out] receives the life span of the security context
                }
                else
                {
                    ss = AcceptSecurityContext(ref _hCred,        // [in] handle to the credentials
                        ref _hContext,                // [in/out] handle of partially formed context.  Always NULL the first time through
                        ref ClientToken,            // [in] pointer to the input buffers
                        STANDARD_CONTEXT_ATTRIBUTES,                        // [in] required context attributes
                        SECURITY_NATIVE_DREP,    // [in] data representation on the target
                        out _hContext,    // [in/out] receives the new context handle    
                        out ServerToken,        // [in/out] pointer to the output buffers
                        out uNewContextAttr,    // [out] receives the context attributes        
                        out NewLifeTime);        // [out] receives the life span of the security context
                }

                if (ss != SEC_E_OK && ss != SEC_I_CONTINUE_NEEDED)
                {
                    throw new Exception("AcceptSecurityContext() failed!!!");
                }

                serverToken = ServerToken.GetSecBufferByteArray();

                bContinueProcessing = ss != SEC_E_OK;
            }
            finally
            {
                ClientToken.Dispose();
                ServerToken.Dispose();
            }
        }

        public void EncryptMessage(byte[] message, out byte[] encryptedBuffer)
        {
            encryptedBuffer = null;

            SecPkgContext_Sizes ContextSizes = new SecPkgContext_Sizes();

            if (QueryContextAttributes(ref _hContext, SECPKG_ATTR_SIZES, out ContextSizes) != SEC_E_OK)
            {
                throw new Exception("QueryContextAttribute() failed!!!");
            }

            MultipleSecBufferHelper[] ThisSecHelper = new MultipleSecBufferHelper[2];
            ThisSecHelper[0] = new MultipleSecBufferHelper(message, SecBufferType.SECBUFFER_DATA);
            ThisSecHelper[1] = new MultipleSecBufferHelper(new byte[ContextSizes.cbSecurityTrailer], SecBufferType.SECBUFFER_TOKEN);

            SecBufferDesc DescBuffer = new SecBufferDesc(ThisSecHelper);

            try
            {
                if (EncryptMessage(ref _hContext, 0, ref DescBuffer, 0) != SEC_E_OK)
                {
                    throw new Exception("EncryptMessage() failed!!!");
                }

                encryptedBuffer = DescBuffer.GetSecBufferByteArray();
            }
            finally
            {
                DescBuffer.Dispose();
            }
        }

        public void DecryptMessage(int messageLength, byte[] encryptedBuffer, bool bUseClientContext,
                                    out byte[] decryptedBuffer)
        {
            decryptedBuffer = null;

            SECURITY_HANDLE DecryptionContext = _hContext;

            if (bUseClientContext)
            {
                DecryptionContext = _hContext;
            }

            byte[] EncryptedMessage = new byte[messageLength];
            Array.Copy(encryptedBuffer, 0, EncryptedMessage, 0, messageLength);

            int SecurityTrailerLength = encryptedBuffer.Length - messageLength;

            byte[] SecurityTrailer = new byte[SecurityTrailerLength];
            Array.Copy(encryptedBuffer, messageLength, SecurityTrailer, 0, SecurityTrailerLength);

            MultipleSecBufferHelper[] ThisSecHelper = new MultipleSecBufferHelper[2];
            ThisSecHelper[0] = new MultipleSecBufferHelper(EncryptedMessage, SecBufferType.SECBUFFER_DATA);
            ThisSecHelper[1] = new MultipleSecBufferHelper(SecurityTrailer, SecBufferType.SECBUFFER_TOKEN);
            SecBufferDesc DescBuffer = new SecBufferDesc(ThisSecHelper);
            try
            {
                uint EncryptionQuality = 0;

                if (DecryptMessage(ref DecryptionContext, ref DescBuffer, 0, out EncryptionQuality) != SEC_E_OK)
                {
                    throw new Exception("DecryptMessage() failed!!!");
                }

                decryptedBuffer = new byte[messageLength];
                Array.Copy(DescBuffer.GetSecBufferByteArray(), 0, decryptedBuffer, 0, messageLength);
            }
            finally
            {
                DescBuffer.Dispose();
            }
        }

        public void SignMessage(byte[] message, out byte[] signedBuffer)
        {
            signedBuffer = null;


            SecPkgContext_Sizes ContextSizes = new SecPkgContext_Sizes();

            if (QueryContextAttributes(ref _hContext, SECPKG_ATTR_SIZES, out ContextSizes) != SEC_E_OK)
            {
                throw new Exception("QueryContextAttribute() failed!!!");
            }

            MultipleSecBufferHelper[] ThisSecHelper = new MultipleSecBufferHelper[2];
            ThisSecHelper[0] = new MultipleSecBufferHelper(message, SecBufferType.SECBUFFER_DATA);
            ThisSecHelper[1] = new MultipleSecBufferHelper(new byte[ContextSizes.cbMaxSignature], SecBufferType.SECBUFFER_TOKEN);

            SecBufferDesc DescBuffer = new SecBufferDesc(ThisSecHelper);

            try
            {
                if (MakeSignature(ref _hContext, 0, ref DescBuffer, 0) != SEC_E_OK)
                {
                    throw new Exception("MakeSignature() failed!!!");
                }

                //SSPIHelper.SignAndVerify(ref _hClientContext,ref hServerContext,ref DescBuffer);
                uint EncryptionQuality = 0;
                VerifySignature(ref this._hContext, ref DescBuffer, 0, out EncryptionQuality);

                signedBuffer = DescBuffer.GetSecBufferByteArray();
            }
            finally
            {
                DescBuffer.Dispose();
            }
        }

        public void VerifyMessage(int messageLength, byte[] signedBuffer, out byte[] verifiedBuffer)
        {
            verifiedBuffer = null;

            byte[] SignedMessage = new byte[messageLength];
            Array.Copy(signedBuffer, 0, SignedMessage, 0, messageLength);

            int SignatureLength = signedBuffer.Length - messageLength;

            byte[] Signature = new byte[SignatureLength];
            Array.Copy(signedBuffer, messageLength, Signature, 0, SignatureLength);

            MultipleSecBufferHelper[] ThisSecHelper = new MultipleSecBufferHelper[2];
            ThisSecHelper[0] = new MultipleSecBufferHelper(SignedMessage, SecBufferType.SECBUFFER_DATA);
            ThisSecHelper[1] = new MultipleSecBufferHelper(Signature, SecBufferType.SECBUFFER_TOKEN);
            SecBufferDesc DescBuffer = new SecBufferDesc(ThisSecHelper);
            try
            {
                uint EncryptionQuality = 0;

                int Return = VerifySignature(ref _hContext, ref DescBuffer, 0, out EncryptionQuality);

                if (Return != SEC_E_OK)
                {
                    throw new Exception("VerifySignature() failed!!!");
                }

                verifiedBuffer = new byte[messageLength];
                Array.Copy(DescBuffer.GetSecBufferByteArray(), 0, verifiedBuffer, 0, messageLength);
            }
            finally
            {
                DescBuffer.Dispose();
            }
        }

        public byte[] GetSessionKey()
        {
            SecPkgContext_SessionKey ContextSessionKey;
            if (QueryContextAttributes(ref _hContext, SECPKG_ATTR_SESSION_KEY, out ContextSessionKey) != SEC_E_OK)
            {
                throw new Exception("QueryContextAttribute() failed!!!");
            }

            var output = new byte[ContextSessionKey.SessionKeyLength];
            Marshal.Copy(ContextSessionKey.Sessionkey, output, 0, (int)ContextSessionKey.SessionKeyLength);
            return output;
        }
    }
}
