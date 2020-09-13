namespace PingCastle.ADWS
{
    public interface IADConnection
    {
        ADDomainInfo GetDomainInfo();

        void Enumerate(string distinguishedName, string filter, string[] properties, WorkOnReturnedObjectByADWS callback, string scope);
    }
}