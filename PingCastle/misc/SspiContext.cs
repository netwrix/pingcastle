using System;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Authentication.ExtendedProtection;

namespace PingCastle.misc
{
    // Wraps the Windows SSPI API (secur32.dll) to perform Negotiate/NTLM/Kerberos
    // authentication with explicit control over context flags.
    //
    // This exists because .NET 8's NegotiateAuthentication does not expose the
    // ISC_REQ_NO_INTEGRITY flag. Without this flag, Kerberos auto-negotiates
    // message integrity, making it impossible to test whether a server actually
    // requires LDAP signing.
    //
    // Key SSPI flags from SSPI.h:
    //   ISC_REQ_INTEGRITY    (0x00010000) - Request message signing
    //   ISC_REQ_NO_INTEGRITY (0x00800000) - Explicitly disable message signing
    //
    // When ISC_REQ_NO_INTEGRITY is set and the server requires signing, the LDAP
    // server will reject the SASL bind because the security context lacks integrity.
    // When ISC_REQ_INTEGRITY is set, signing is negotiated and the bind succeeds.
    // Comparing these two outcomes detects signing enforcement.
    sealed class SspiContext : IDisposable
    {
        const int SecpkgCredOutbound = 2;
        const int SecurityNativeDrep = 0x10;
        const int SecBufferToken = 2;
        const int SecBufferChannelBindings = 14;
        const int SecBufferVersion = 0;
        const int SecEOk = 0;
        const int SecIContinueNeeded = 0x00090312;
        const int IscReqConnection = 0x00000800;
        const int IscReqIntegrity = 0x00010000;
        const int IscReqNoIntegrity = 0x00800000;
        const int SecWinntAuthIdentityUnicode = 2;
        const int MaxTokenSize = 65536;

        [StructLayout(LayoutKind.Sequential)]
        struct SecurityHandle
        {
            public IntPtr LowPart;
            public IntPtr HighPart;

            public bool IsValid => LowPart != IntPtr.Zero || HighPart != IntPtr.Zero;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct SecBuffer
        {
            public int Count;
            public int Type;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct SecBufferDesc
        {
            public int Version;
            public int NumBuffers;
            public IntPtr BuffersPtr;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct SecWinntAuthIdentity
        {
            public string User;
            public int UserLength;
            public string Domain;
            public int DomainLength;
            public string Password;
            public int PasswordLength;
            public int Flags;
        }

        [DllImport("secur32.dll", CharSet = CharSet.Unicode, SetLastError = false)]
        static extern int AcquireCredentialsHandle(
            string principal,
            string package,
            int credentialUse,
            IntPtr logonId,
            IntPtr authData,
            IntPtr getKeyFn,
            IntPtr getKeyArg,
            ref SecurityHandle credential,
            out long expiry);

        [DllImport("secur32.dll", CharSet = CharSet.Unicode, SetLastError = false)]
        static extern int InitializeSecurityContext(
            ref SecurityHandle credential,
            IntPtr context,
            string targetName,
            int contextReq,
            int reserved1,
            int targetDataRep,
            IntPtr inputBuffer,
            int reserved2,
            ref SecurityHandle newContext,
            ref SecBufferDesc outputBuffer,
            out int contextAttr,
            out long expiry);

        [DllImport("secur32.dll", CharSet = CharSet.Unicode, SetLastError = false)]
        static extern int InitializeSecurityContext(
            ref SecurityHandle credential,
            ref SecurityHandle context,
            string targetName,
            int contextReq,
            int reserved1,
            int targetDataRep,
            ref SecBufferDesc inputBuffer,
            int reserved2,
            ref SecurityHandle newContext,
            ref SecBufferDesc outputBuffer,
            out int contextAttr,
            out long expiry);

        [DllImport("secur32.dll")]
        static extern int DeleteSecurityContext(ref SecurityHandle context);

        [DllImport("secur32.dll")]
        static extern int FreeCredentialsHandle(ref SecurityHandle credential);

        [DllImport("secur32.dll")]
        static extern int FreeContextBuffer(IntPtr buffer);

        SecurityHandle _credHandle;
        SecurityHandle _ctxHandle;
        bool _hasContext;
        int _contextFlags;
        string _package;
        string _targetName;
        ChannelBinding _channelBinding;
        bool _disposed;

        // Acquires SSPI credentials and sets context flags for subsequent calls to GetToken.
        //
        // When disableSigning is true, ISC_REQ_NO_INTEGRITY is used to explicitly tell SSPI
        // not to negotiate message signing. This is different from simply omitting
        // ISC_REQ_INTEGRITY — without the explicit NO_INTEGRITY flag, Kerberos will
        // auto-negotiate signing and the server will accept the bind even when it
        // requires signing, producing a false negative in signing detection.
        public void Initialize(string package, bool disableSigning, NetworkCredential credential, ChannelBinding channelBinding)
        {
            _package = package;
            _channelBinding = channelBinding;
            _contextFlags = IscReqConnection | (disableSigning ? IscReqNoIntegrity : IscReqIntegrity);

            Trace.WriteLine("SspiContext: flags=0x" + _contextFlags.ToString("X8")
                + " (" + (disableSigning ? "ISC_REQ_NO_INTEGRITY" : "ISC_REQ_INTEGRITY") + ")");

            IntPtr authDataPtr = IntPtr.Zero;
            GCHandle authDataHandle = default;

            try
            {
                if (credential != null && credential != CredentialCache.DefaultCredentials)
                {
                    var authData = new SecWinntAuthIdentity
                    {
                        User = credential.UserName,
                        UserLength = credential.UserName?.Length ?? 0,
                        Domain = credential.Domain,
                        DomainLength = credential.Domain?.Length ?? 0,
                        Password = credential.Password,
                        PasswordLength = credential.Password?.Length ?? 0,
                        Flags = SecWinntAuthIdentityUnicode,
                    };
                    authDataHandle = GCHandle.Alloc(authData, GCHandleType.Pinned);
                    authDataPtr = authDataHandle.AddrOfPinnedObject();
                }

                int result = AcquireCredentialsHandle(
                    null, package, SecpkgCredOutbound,
                    IntPtr.Zero, authDataPtr,
                    IntPtr.Zero, IntPtr.Zero,
                    ref _credHandle, out _);

                if (result != SecEOk)
                {
                    Trace.WriteLine("SspiContext: AcquireCredentialsHandle failed with 0x" + result.ToString("X8"));
                    throw new InvalidOperationException("AcquireCredentialsHandle failed with 0x" + result.ToString("X8"));
                }
            }
            finally
            {
                if (authDataHandle.IsAllocated)
                {
                    authDataHandle.Free();
                }
            }
        }

        // Performs one round of the SSPI handshake. Returns the outgoing token to send
        // to the server, or null if the handshake failed.
        // Called repeatedly by ConnectionTesterLdap/Http until auth completes or fails.
        public byte[] GetToken(byte[] incomingToken)
        {
            var outBuffer = new SecBuffer
            {
                Count = MaxTokenSize,
                Type = SecBufferToken,
                Buffer = Marshal.AllocHGlobal(MaxTokenSize),
            };

            var outBufferHandle = GCHandle.Alloc(outBuffer, GCHandleType.Pinned);
            var outDesc = new SecBufferDesc
            {
                Version = SecBufferVersion,
                NumBuffers = 1,
                BuffersPtr = outBufferHandle.AddrOfPinnedObject(),
            };

            GCHandle cbBufferHandle = default;
            GCHandle inBuffersArrayHandle = default;
            IntPtr cbDataPtr = IntPtr.Zero;

            try
            {
                int result;

                if (!_hasContext)
                {
                    // First call: no existing context. Pass channel binding if available.
                    if (_channelBinding != null)
                    {
                        byte[] cbBytes = GetChannelBindingBytes(_channelBinding);
                        cbDataPtr = Marshal.AllocHGlobal(cbBytes.Length);
                        Marshal.Copy(cbBytes, 0, cbDataPtr, cbBytes.Length);

                        var cbBuffer = new SecBuffer
                        {
                            Count = cbBytes.Length,
                            Type = SecBufferChannelBindings,
                            Buffer = cbDataPtr,
                        };

                        cbBufferHandle = GCHandle.Alloc(cbBuffer, GCHandleType.Pinned);
                        var inDesc = new SecBufferDesc
                        {
                            Version = SecBufferVersion,
                            NumBuffers = 1,
                            BuffersPtr = cbBufferHandle.AddrOfPinnedObject(),
                        };

                        result = InitializeSecurityContext(
                            ref _credHandle, ref _ctxHandle, _targetName,
                            _contextFlags, 0, SecurityNativeDrep,
                            ref inDesc, 0,
                            ref _ctxHandle, ref outDesc,
                            out _, out _);
                    }
                    else
                    {
                        result = InitializeSecurityContext(
                            ref _credHandle, IntPtr.Zero, _targetName,
                            _contextFlags, 0, SecurityNativeDrep,
                            IntPtr.Zero, 0,
                            ref _ctxHandle, ref outDesc,
                            out _, out _);
                    }

                    _hasContext = true;
                }
                else
                {
                    // Subsequent calls: pass the server's response token (and channel binding).
                    IntPtr inTokenPtr = IntPtr.Zero;
                    try
                    {
                        int numInBuffers = 1;
                        SecBuffer[] inBuffers;

                        if (incomingToken != null && incomingToken.Length > 0)
                        {
                            inTokenPtr = Marshal.AllocHGlobal(incomingToken.Length);
                            Marshal.Copy(incomingToken, 0, inTokenPtr, incomingToken.Length);
                        }

                        if (_channelBinding != null)
                        {
                            byte[] cbBytes = GetChannelBindingBytes(_channelBinding);
                            cbDataPtr = Marshal.AllocHGlobal(cbBytes.Length);
                            Marshal.Copy(cbBytes, 0, cbDataPtr, cbBytes.Length);

                            numInBuffers = 2;
                            inBuffers = new SecBuffer[2];
                            inBuffers[0] = new SecBuffer
                            {
                                Count = incomingToken?.Length ?? 0,
                                Type = SecBufferToken,
                                Buffer = inTokenPtr,
                            };
                            inBuffers[1] = new SecBuffer
                            {
                                Count = cbBytes.Length,
                                Type = SecBufferChannelBindings,
                                Buffer = cbDataPtr,
                            };
                        }
                        else
                        {
                            inBuffers = new SecBuffer[1];
                            inBuffers[0] = new SecBuffer
                            {
                                Count = incomingToken?.Length ?? 0,
                                Type = SecBufferToken,
                                Buffer = inTokenPtr,
                            };
                        }

                        inBuffersArrayHandle = GCHandle.Alloc(inBuffers, GCHandleType.Pinned);
                        var inDesc = new SecBufferDesc
                        {
                            Version = SecBufferVersion,
                            NumBuffers = numInBuffers,
                            BuffersPtr = inBuffersArrayHandle.AddrOfPinnedObject(),
                        };

                        result = InitializeSecurityContext(
                            ref _credHandle, ref _ctxHandle, _targetName,
                            _contextFlags, 0, SecurityNativeDrep,
                            ref inDesc, 0,
                            ref _ctxHandle, ref outDesc,
                            out _, out _);
                    }
                    finally
                    {
                        if (inTokenPtr != IntPtr.Zero)
                        {
                            Marshal.FreeHGlobal(inTokenPtr);
                        }
                    }
                }

                if (result != SecEOk && result != SecIContinueNeeded)
                {
                    Trace.WriteLine("SspiContext: InitializeSecurityContext failed with 0x" + result.ToString("X8"));
                    return null;
                }

                outBuffer = Marshal.PtrToStructure<SecBuffer>(outBufferHandle.AddrOfPinnedObject());
                if (outBuffer.Count > 0 && outBuffer.Buffer != IntPtr.Zero)
                {
                    byte[] token = new byte[outBuffer.Count];
                    Marshal.Copy(outBuffer.Buffer, token, 0, outBuffer.Count);
                    return token;
                }

                return Array.Empty<byte>();
            }
            finally
            {
                if (outBuffer.Buffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(outBuffer.Buffer);
                }

                if (outBufferHandle.IsAllocated)
                {
                    outBufferHandle.Free();
                }

                if (cbBufferHandle.IsAllocated)
                {
                    cbBufferHandle.Free();
                }

                if (inBuffersArrayHandle.IsAllocated)
                {
                    inBuffersArrayHandle.Free();
                }

                if (cbDataPtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(cbDataPtr);
                }
            }
        }

        static byte[] GetChannelBindingBytes(ChannelBinding binding)
        {
            int size = binding.Size;
            byte[] data = new byte[size];
            Marshal.Copy(binding.DangerousGetHandle(), data, 0, size);
            return data;
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;

            if (_hasContext)
            {
                DeleteSecurityContext(ref _ctxHandle);
            }

            if (_credHandle.IsValid)
            {
                FreeCredentialsHandle(ref _credHandle);
            }
        }
    }
}
