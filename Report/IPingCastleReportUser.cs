using PingCastle.Cloud.Data;
using PingCastle.Data;

namespace PingCastle.Report
{
    public delegate string GetUrlDelegateDomain(DomainKey domainKey, string displayName, string optionalRiskId);
    public delegate string GetUrlDelegateAzureAD(AzureADKey domainKey, string displayName, string optionalRiskId);
    public delegate string GetAdditionInfoDelegate(DomainKey domainKey);
    public delegate string AddHtmlToTabSection(string section);

    public interface IPingCastleReportUser<T> where T : IPingCastleReport
    {
        string GenerateReportFile(T report, string filename);
        string GenerateRawContent(T report);
        void SetUrlDisplayDelegate(GetUrlDelegateDomain uRLDelegate);
        void SetUrlDisplayDelegate(GetUrlDelegateAzureAD uRLDelegate);
    }
}
