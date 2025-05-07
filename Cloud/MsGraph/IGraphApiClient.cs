using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Graph.Beta.Models;

namespace PingCastle.Cloud.MsGraph
{
    public interface IGraphApiClient
    {
        Task<Organization> GetCompanyInfoAsync();
        Task<AuthorizationPolicy> GetAuthorizationPolicyAsync();
        Task<OnPremisesDirectorySynchronization> GetOnPremisesDirectorySynchronizationAsync();
        Task<IReadOnlyList<LicenseDetails>> GetUserLicensesAsync(string userId);
        IAsyncEnumerable<DirectoryRole> GetRolesAsync();
        IAsyncEnumerable<DirectoryRoleTemplate> GetRoleTemplatesAsync();
        Task<IReadOnlyList<Domain>> GetDomainsAsync();
        Task<IReadOnlyList<DomainDnsRecord>> GetDomainDnsRecordsAsync(string domainName);
        IAsyncEnumerable<UserRegistrationDetails> GetUserRegistrationDetailsAsync();
    }
}
