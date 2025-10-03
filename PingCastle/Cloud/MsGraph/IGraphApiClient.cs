using System;
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
        Task<User> GetUserByIdAsync(string userId, IEnumerable<string> selectProperties = null);
        IAsyncEnumerable<DirectoryObject> GetGroupDirectMembersAsync(string groupId);
        IAsyncEnumerable<User> GetGroupTransitiveMembersAsync(string groupId);
        IAsyncEnumerable<User> GetAllUsersAsync(IEnumerable<string> selectProperties = null, string filter = null);
        IAsyncEnumerable<DirectoryObject> GetUserMembershipAsync(string userId);
        IAsyncEnumerable<DirectoryRole> GetRolesAsync();
        IAsyncEnumerable<DirectoryRoleTemplate> GetRoleTemplatesAsync();
        Task<IReadOnlyList<Domain>> GetDomainsAsync();
        Task<IReadOnlyList<DomainDnsRecord>> GetDomainDnsRecordsAsync(string domainName);
        IAsyncEnumerable<UserRegistrationDetails> GetUserRegistrationDetailsAsync();
        IAsyncEnumerable<NamedLocation> GetNamedLocationsAsync();
        Task<CrossTenantAccessPolicy> GetCrossTenantAccessPolicyAsync();
        IAsyncEnumerable<CrossTenantAccessPolicyConfigurationPartner> GetPartnerCrossTenantAccessPoliciesAsync();
        Task<DateTime?> GetPolicyLastModificationDate(string policyId);
        IAsyncEnumerable<ServicePrincipal> GetAllServicePrincipalsAsync();
        IAsyncEnumerable<OAuth2PermissionGrant> GetAllOAuth2PermissionGrantsAsync();
        Task<IReadOnlyList<AppRole>> GetServicePrincipalAppRolesAsync(string servicePrincipalId);
        IAsyncEnumerable<AppRoleAssignment> GetAppRoleAssignmentsToServicePrincipalAsync(string servicePrincipalId);
        IAsyncEnumerable<DirectoryObject> GetServicePrincipalMembershipAsync(string servicePrincipalId);
    }
}
