//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Healthcheck;
using System;
using System.Runtime.Serialization;
using System.Security.Permissions;

namespace PingCastle.Scanners
{
    [Serializable]
    public class SmbScannerException : Exception
    {
        public string Server { get; set; }

        public SmbScannerException(string server, string message)
            : base(message)
        {
            Server = server;
        }
        protected SmbScannerException(System.Runtime.Serialization.SerializationInfo info,
            System.Runtime.Serialization.StreamingContext context)
            : base(info, context)
        {
            this.Server = info.GetString("Server");
        }

        [SecurityPermissionAttribute(SecurityAction.Demand, SerializationFormatter = true)]
        public override void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            if (info == null)
            {
                throw new ArgumentNullException("info");
            }

            info.AddValue("Server", this.Server);

            // MUST call through to the base class to let it save its own state
            base.GetObjectData(info, context);
        }
    }

    [Serializable]
    public class SmbPortClosedException : SmbScannerException
    {
        public SmbPortClosedException(string server)
            : base(server, "The SMB port (tcp/445) is not open (" + server + ")")
        {
        }
    }

    [Serializable]
    public class Smb1NotSupportedException : SmbScannerException
    {
        public Smb1NotSupportedException(string server)
            : base(server, "The SMB v1 protocol is not supported (" + server + ")")
        {
        }
    }

    [Serializable]
    public class Smb2NotSupportedException : SmbScannerException
    {
        public Smb2NotSupportedException(string server)
            : base(server, "The SMB v2 protocol (also used in SMBv3) is not supported (" + server + ")")
        {
        }
    }

    [Serializable]
    public class Smb2NotWellFormatedException : SmbScannerException
    {
        public Smb2NotWellFormatedException(string server)
            : base(server, "Invalid SMB dialog (" + server + ")")
        {
        }
    }

    public class SmbScanner : ScannerBase
    {
        public static bool DoNotTestSMBv1;

        public static bool SupportSMB1(string server, out SMBSecurityModeEnum securityMode, string logPrefix)
        {
            securityMode = SMBSecurityModeEnum.NotTested;
            try
            {
                if (DoNotTestSMBv1)
                    return false;
                return Smb1Protocol.DoesServerSupportDialect(server, "NT LM 0.12", out securityMode, logPrefix);
            }
            catch (Exception)
            {
                return false;
            }
        }

        public static bool SupportSMB2And3(string server, out SMBSecurityModeEnum securityMode, string logPrefix)
        {
            bool tempResult = false;
            bool result = false;
            securityMode = SMBSecurityModeEnum.NotTested;
            SMBSecurityModeEnum smbv2temp;
            foreach (int dialect in new int[] { 0x0202, 0x0210, 0x0300, 0x0302, 0x0311 })
            {
                try
                {
                    tempResult = Smb2ProtocolTest.DoesServerSupportDialectWithSmbV2(server, dialect, out smbv2temp, logPrefix);
                    if (tempResult)
                    {
                        result = true;
                        securityMode = CombineSecurityMode(securityMode, smbv2temp);
                    }
                }
                catch (SmbPortClosedException)
                {
                    break;
                }
                catch (Exception)
                {
                }
            }
            return result;
        }

        public override string Name { get { return "smb"; } }
        public override string Description { get { return "Scan a computer and determine the smb version available. Also if SMB signing is active."; } }

        override protected string GetCsvHeader()
        {
            return "Computer\tSMB Port Open\tSMB1 with dialect NT LM 0.12\tSMB1 Sign Required\tSMB2 with dialect 0x0202\tSMB2 with dialect 0x0210\tSMB3 with dialect 0x0300\tSMB3 with dialect 0x0302\tSMB3 with dialect 0x0311\tSMB2 and SMB3 message Signature Required";
        }

        override protected string GetCsvData(string computer)
        {
            bool isPortOpened = true;
            bool SMBv1 = false;
            bool SMBv2_0x0202 = false;
            bool SMBv2_0x0210 = false;
            bool SMBv2_0x0300 = false;
            bool SMBv2_0x0302 = false;
            bool SMBv2_0x0311 = false;
            SMBSecurityModeEnum smbv1secmode = SMBSecurityModeEnum.NotTested;
            SMBSecurityModeEnum smbv2secmode = SMBSecurityModeEnum.NotTested;
            SMBSecurityModeEnum smbv2temp;
            try
            {
                try
                {
                    SMBv1 = Smb1Protocol.DoesServerSupportDialect(computer, "NT LM 0.12", out smbv1secmode);
                }
                catch (Smb1NotSupportedException)
                {
                }
                try
                {
                    SMBv2_0x0202 = Smb2ProtocolTest.DoesServerSupportDialectWithSmbV2(computer, 0x0202, out smbv2secmode);
                    SMBv2_0x0210 = Smb2ProtocolTest.DoesServerSupportDialectWithSmbV2(computer, 0x0210, out smbv2temp);
                    smbv2secmode = CombineSecurityMode(smbv2secmode, smbv2temp);
                    SMBv2_0x0300 = Smb2ProtocolTest.DoesServerSupportDialectWithSmbV2(computer, 0x0300, out smbv2temp);
                    smbv2secmode = CombineSecurityMode(smbv2secmode, smbv2temp);
                    SMBv2_0x0302 = Smb2ProtocolTest.DoesServerSupportDialectWithSmbV2(computer, 0x0302, out smbv2temp);
                    smbv2secmode = CombineSecurityMode(smbv2secmode, smbv2temp);
                    SMBv2_0x0311 = Smb2ProtocolTest.DoesServerSupportDialectWithSmbV2(computer, 0x0311, out smbv2temp);
                    smbv2secmode = CombineSecurityMode(smbv2secmode, smbv2temp);
                }
                catch (Smb2NotSupportedException)
                {
                }
            }
            catch (SmbPortClosedException)
            {
                isPortOpened = false;
            }
            return computer + "\t" + (isPortOpened ? "Yes" : "No") + "\t" + (SMBv1 ? "Yes" : "No")
                                                            + "\t" + ((smbv1secmode & SMBSecurityModeEnum.SmbSigningRequired) != 0 ? "Yes" : "No")
                                                            + "\t" + (SMBv2_0x0202 ? "Yes" : "No")
                                                            + "\t" + (SMBv2_0x0210 ? "Yes" : "No")
                                                            + "\t" + (SMBv2_0x0300 ? "Yes" : "No")
                                                            + "\t" + (SMBv2_0x0302 ? "Yes" : "No")
                                                            + "\t" + (SMBv2_0x0311 ? "Yes" : "No")
                                                            + "\t" + ((smbv2secmode & SMBSecurityModeEnum.SmbSigningRequired) != 0 ? "Yes" : "No");
        }

        private static SMBSecurityModeEnum CombineSecurityMode(SMBSecurityModeEnum smbv2secmode, SMBSecurityModeEnum smbv2temp)
        {
            if (smbv2temp == SMBSecurityModeEnum.NotTested)
                return smbv2secmode;
            if (smbv2secmode == SMBSecurityModeEnum.NotTested)
                return smbv2temp;
            if (smbv2temp == SMBSecurityModeEnum.None || smbv2secmode == SMBSecurityModeEnum.None)
                return SMBSecurityModeEnum.None;
            if ((smbv2temp & SMBSecurityModeEnum.SmbSigningEnabled) != 0 && (smbv2secmode & SMBSecurityModeEnum.SmbSigningEnabled) != 0)
            {
                if ((smbv2temp & SMBSecurityModeEnum.SmbSigningRequired) != 0 && (smbv2secmode & SMBSecurityModeEnum.SmbSigningRequired) != 0)
                {
                    return SMBSecurityModeEnum.SmbSigningEnabled | SMBSecurityModeEnum.SmbSigningRequired;
                }
                return SMBSecurityModeEnum.SmbSigningEnabled;
            }
            // defensive programming
            return SMBSecurityModeEnum.NotTested;
        }

    }
}
