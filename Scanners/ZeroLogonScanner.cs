using System.Runtime.InteropServices;

namespace PingCastle.Scanners
{
    public class ZeroLogonScanner : ScannerBase
    {

        public override string Name { get { return "zerologon"; } }
        public override string Description { get { return "Test for the ZeroLogon vulnerability. Important: the tester must be inside the domain. Trusts cannot be used."; } }

        override protected string GetCsvHeader()
        {
            return "Computer\tISVulnerable";
        }

        public override DisplayState QueryForAdditionalParameterInInteractiveMode()
        {
            ScanningMode = 5;
            return Settings.EnsureDataCompleted("Server");
        }

        protected override string GetCsvData(string computer)
        {
            int NegotiateFlags = 0x212fffff;
            int ServerSecureChannel = 6;
            int r = 0;
            for (int i = 0; i < 2000; i++)
            {
                var Input = new NETLOGON_CREDENTIAL();
                Input.data = new byte[8];
                var LazyOutput = new NETLOGON_CREDENTIAL();
                LazyOutput.data = new byte[8];

                string dcname = computer.Split('.')[0];

                r = I_NetServerReqChallenge(computer, dcname, ref Input, out LazyOutput);
                if (r != 0)
                {
                    return computer + "\t" + "Error 1: " + r.ToString("x");
                }
                r = I_NetServerAuthenticate2(computer, dcname + "$", ServerSecureChannel, dcname, ref Input, out LazyOutput, ref NegotiateFlags);
                if (r == 0)
                {
                    return computer + "\t" + "Vulnerable after " + i + " attempts";
                }
                else if ((uint)r != 0xc0000022)
                {
                    return computer + "\t" + "Error 3: " + r.ToString("x");
                }
            }
            return computer + "\t" + "Error 2: " + r.ToString("x");
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct NETLOGON_CREDENTIAL
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] data;
        }

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern int I_NetServerReqChallenge(string domain, string computer, ref NETLOGON_CREDENTIAL ClientChallenge, out NETLOGON_CREDENTIAL ServerChallenge);
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern int I_NetServerAuthenticate2(string domain, string account, int SecureChannelType, string computername, ref NETLOGON_CREDENTIAL ClientCredential, out NETLOGON_CREDENTIAL ServerCredential, ref int NegotiateFlags);

    }
}
