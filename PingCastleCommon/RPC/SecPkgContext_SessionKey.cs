namespace PingCastle.RPC
{
    using System;
    using System.Runtime.InteropServices;

    [StructLayout(LayoutKind.Sequential)]
    public struct SecPkgContext_SessionKey
    {
        public uint SessionKeyLength;
        public IntPtr Sessionkey;
    }

;
}