//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Diagnostics;
using System.Net;
using System.Reflection;
using System.Security.Principal;
using System.Threading;

namespace PingCastle.ADWS
{
    public abstract class ADConnection : IADConnection
    {

        public abstract void Enumerate(string distinguishedName, string filter, string[] properties, WorkOnReturnedObjectByADWS callback, string scope);
        public abstract void EstablishConnection();

        public string Server { get; set; }

        public int Port { get; set; }

        public static int RecordPerSeconds = int.MaxValue;
        int CurrentRecords = 0;

        public NetworkCredential Credential { get; set; }

        protected DateTime ConnectionTime;

        protected abstract ADDomainInfo GetDomainInfoInternal();
        protected ADDomainInfo domainInfo;

        public ADDomainInfo GetDomainInfo()
        {
            if (domainInfo == null)
            {
                ConnectionTime = DateTime.Now;
                domainInfo = GetDomainInfoInternal();
            }
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

        public virtual string ConvertSIDToName(string sidstring, out string referencedDomain)
        {
            WindowsIdentity identity = null;
            WindowsImpersonationContext context = null;
            try
            {
                if (this.Credential != null)
                {
                    identity = WindowsFileConnection.GetWindowsIdentityForUser(this.Credential, this.Server);
                    context = identity.Impersonate();
                }

                return NativeMethods.ConvertSIDToNameWithWindowsAPI(sidstring, this.Server, out referencedDomain);
            }
            finally
            {
                context?.Undo();
                identity?.Dispose();
            }
        }

        public abstract SecurityIdentifier ConvertNameToSID(string nameToResolve);

        public abstract IFileConnection FileConnection {get;}

        protected void OneRecord()
        {
            CurrentRecords++;
            if (ConnectionTime != default(DateTime) && RecordPerSeconds < int.MaxValue)
            {
                var elapsedSeconds = (DateTime.Now - ConnectionTime).TotalSeconds;
                var quota = elapsedSeconds * RecordPerSeconds;
                if (CurrentRecords > quota)
                {
                    Trace.WriteLine("Sleeping 1s for LDAP quota");
                    Thread.Sleep(1000);
                }
            }
        }

        public abstract void ThreadInitialization();
    }
}
