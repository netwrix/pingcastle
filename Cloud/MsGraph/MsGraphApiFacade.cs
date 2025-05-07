using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Microsoft.Graph.Beta;
using Microsoft.Graph.Beta.Models;
using PingCastle.Cloud.MsGraph;
using PingCastle.Cloud.RESTServices.Azure;

namespace PingCastle.Cloud
{
    [AzureService("1b730954-1685-4b74-9bfd-dac224a7b894", "https://graph.microsoft.com")]
    [EndPoint("https://login.microsoftonline.com/common/oauth2/v2.0/authorize", "https://login.microsoftonline.com/common/oauth2/v2.0/token", "https://graph.microsoft.com/.default")]
    public class MsGraphApiFacade : IAzureService, IGraphApiClient
    {
        private readonly GraphServiceClient _client;

        public MsGraphApiFacade(GraphServiceClient client)
        {
            _client = client;
        }

        public async Task<Organization> GetCompanyInfoAsync()
        {
            var companies = await _client.Organization.GetAsync();
            return companies.Value.FirstOrDefault();
        }

        public async Task<AuthorizationPolicy> GetAuthorizationPolicyAsync()
        {
            var policies = await _client.Policies.AuthorizationPolicy.GetAsync();
            return policies.Value.FirstOrDefault();
        }
     
        public async Task<OnPremisesDirectorySynchronization> GetOnPremisesDirectorySynchronizationAsync()
        {
            var onPremSync = await _client.Directory.OnPremisesSynchronization.GetAsync();
            return onPremSync.Value.FirstOrDefault();
        }

        public async Task<IReadOnlyList<LicenseDetails>> GetUserLicensesAsync(string userId)
        {
            try
            {
                var licenses = await _client.Users[userId].LicenseDetails.GetAsync();
                return licenses.Value;
            }
            catch (Exception ex)
            {
                Trace.TraceError($"User id: {userId} not found. Error: {ex}");
                return null;
            }
        }

        public async IAsyncEnumerable<DirectoryRole> GetRolesAsync()
        {
            var roles = await _client.DirectoryRoles
                .GetAsync(configuration =>
                {
                    configuration.QueryParameters.Expand = new[] { "members" };
                });

            do
            {
                foreach (var role in roles.Value)
                {
                    yield return role;
                }
            }
            while (roles.OdataNextLink != null &&
                    (roles = await _client.DirectoryRoles.WithUrl(roles.OdataNextLink).GetAsync()) != null);
        }

        public async IAsyncEnumerable<DirectoryRoleTemplate> GetRoleTemplatesAsync()
        {
            var templates = await _client.DirectoryRoleTemplates.GetAsync();

            do
            {
                foreach (var template in templates.Value)
                {
                    yield return template;
                }
            }
            while (templates.OdataNextLink != null &&
                    (templates = await _client.DirectoryRoleTemplates.WithUrl(templates.OdataNextLink).GetAsync()) != null);
        }

        public async Task<IReadOnlyList<Domain>> GetDomainsAsync()
        {
            var domains = await _client.Domains.GetAsync(configuration =>
            {
                configuration.QueryParameters.Expand = new[] { "rootDomain" };
            });
            return domains.Value;
        }

        public async Task<IReadOnlyList<DomainDnsRecord>> GetDomainDnsRecordsAsync(string domainName)
        {
            try
            {
                var records = await _client.Domains[domainName].VerificationDnsRecords.GetAsync();
                return records.Value;
            }
            catch (Exception ex)
            {
                Trace.TraceError($"Domain id: {domainName} not found. Error: {ex}");
                return null;
            }
        }

        public async IAsyncEnumerable<UserRegistrationDetails> GetUserRegistrationDetailsAsync()
        {
            var details = await _client.Reports.AuthenticationMethods.UserRegistrationDetails
                .GetAsync(configuration =>
                {
                    configuration.QueryParameters.Select = new[] { "id", "isMfaRegistered", "isMfaCapable" };
                });

            do
            {
                foreach (var detail in details.Value)
                {
                    yield return detail;
                }
            }
            while (details.OdataNextLink != null &&
                (details = await _client.Reports.AuthenticationMethods.UserRegistrationDetails.WithUrl(details.OdataNextLink).GetAsync()) != null);
        }
    }
}
