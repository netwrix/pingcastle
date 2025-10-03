using System;

namespace PingCastle.Healthcheck
{
    // From https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-csra/509360cf-9797-491e-9dd1-795f63cb1538
    [Flags]
    public enum CertificationAuthorityRights : uint
    {
        ManageCA = 1,               
        ManageCertificates = 2,     
        Auditor = 4,
        Operator = 8,
        Read = 256,
        Enroll = 512,
    }
}
