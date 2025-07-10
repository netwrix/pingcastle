//
// Copyright (c) Vincent LE TOUX for Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace PingCastle.Cloud.RESTServices
{
    [StructLayout(LayoutKind.Sequential)]
    public struct ProofOfPossessionCookieInfo
    {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string Name;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string Data;
        public readonly uint Flags;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string P3PHeader;
    }


    // All these are defined in the Win10 WDK
    [Guid("CDAECE56-4EDF-43DF-B113-88E4556FA1BB")]
    [ComImport]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IProofOfPossessionCookieInfoManager
    {
        int GetCookieInfoForUri(
            [MarshalAs(UnmanagedType.LPWStr)] string Uri,
            out uint cookieInfoCount,
            out IntPtr cookieInfo
        );
    }

    [Guid("A9927F85-A304-4390-8B23-A75F1C668600")]
    [ComImport]
    public class WindowsTokenProvider
    {
    }


    public class CookieInfoManager
    {
        public static List<ProofOfPossessionCookieInfo> GetCookieInforForUri(string uri)
        {
            var output = new List<ProofOfPossessionCookieInfo>();
            IProofOfPossessionCookieInfoManager provider;
            try
            {
                provider = (IProofOfPossessionCookieInfoManager)new WindowsTokenProvider();
            }
            catch (COMException ex)
            {
                throw new ApplicationException("Unable to retrieve the PRT. Is Windows support for AzureAD installed ? (" + ex.Message + "). You should use manual credential to login to AzureAD.");
            }
            IntPtr ptr;
            uint count;
            var error = provider.GetCookieInfoForUri(uri, out count, out ptr);
            if (error != 0)
                throw new COMException("unable to call GetCookieInfoForUri", error);
            var offset = ptr;
            for (int i = 0; i < count; i++)
            {
                var info = (ProofOfPossessionCookieInfo)Marshal.PtrToStructure(offset, typeof(ProofOfPossessionCookieInfo));
                output.Add(info);
            }

            Marshal.FreeCoTaskMem(ptr);
            return output;
        }
    }

}
