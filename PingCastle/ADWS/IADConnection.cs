using System.Security.Principal;

namespace PingCastle.ADWS
{
    public interface IADConnection
    {
        ADDomainInfo GetDomainInfo();

        void Enumerate(string distinguishedName, string filter, string[] properties, WorkOnReturnedObjectByADWS callback, string scope);

        string ConvertSIDToName(string sidstring, out string referencedDomain);

        SecurityIdentifier ConvertNameToSID(string nameToResolve);

        IFileConnection FileConnection { get; }

        void ThreadInitialization();

    }
}
