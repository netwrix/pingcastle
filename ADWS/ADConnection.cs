//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Diagnostics;
using System.Net;
using System.Security.Principal;

namespace PingCastle.ADWS
{
    public abstract class ADConnection : IADConnection
    {

        public abstract void Enumerate(string distinguishedName, string filter, string[] properties, WorkOnReturnedObjectByADWS callback, string scope);
        public abstract void EstablishConnection();

        public string Server { get; set; }

        public int Port { get; set; }

        public NetworkCredential Credential { get; set; }

        protected abstract ADDomainInfo GetDomainInfoInternal();
        protected ADDomainInfo domainInfo;

        public ADDomainInfo GetDomainInfo()
        {
            if (domainInfo == null)
                domainInfo = GetDomainInfoInternal();
            return domainInfo;
        }

        public static string EscapeLDAP(string input)
        {
            string strTemp = input.Replace("\\", "\\5c");
            strTemp = strTemp.Replace("(", "\\28");
            strTemp = strTemp.Replace("|", "\\7c");
            strTemp = strTemp.Replace("<", "\\3c");
            strTemp = strTemp.Replace("/", "\\2f");
            strTemp = strTemp.Replace(")", "\\29");
            strTemp = strTemp.Replace("=", "\\3d");
            strTemp = strTemp.Replace("~", "\\7e");
            strTemp = strTemp.Replace("&", "\\26");
            strTemp = strTemp.Replace(">", "\\3e");
            strTemp = strTemp.Replace("*", "\\2a");
            return strTemp;
        }

        public static string EncodeSidToString(string sid)
        {
            try
            {
                Trace.WriteLine("Encoding sid: " + sid);
                var realsid = new System.Security.Principal.SecurityIdentifier(sid);
                var bytesid = new byte[realsid.BinaryLength];
                realsid.GetBinaryForm(bytesid, 0);
                return "\\" + BitConverter.ToString(bytesid).Replace("-", "\\");
            }
            catch (ArgumentException)
            {
                Trace.WriteLine("Unable to encode " + sid);
                throw;
            }
        }

        public abstract string ConvertSIDToName(string sidstring, out string referencedDomain);

        public abstract SecurityIdentifier ConvertNameToSID(string nameToResolve);

        public abstract IFileConnection FileConnection {get;}



        public abstract void ThreadInitialization();
    }
}
