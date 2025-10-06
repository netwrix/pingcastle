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

        public async Task<CrossTenantAccessPolicy> GetCrossTenantAccessPolicyAsync()
        {
            return await _client.Policies.CrossTenantAccessPolicy.GetAsync();
        }

        public async IAsyncEnumerable<CrossTenantAccessPolicyConfigurationPartner> GetPartnerCrossTenantAccessPoliciesAsync()
        {
            var partnersPage = await _client.Policies.CrossTenantAccessPolicy.Partners.GetAsync(config =>
            {
                config.QueryParameters.Select = new[] {
                    "tenantId",
                    "b2bCollaborationInbound",
                    "b2bCollaborationOutbound",
                    "b2bDirectConnectInbound",
                    "b2bDirectConnectOutbound"
                };
            });

            do
            {
                if (partnersPage?.Value != null)
                {
                    foreach (var partner in partnersPage.Value)
                    {
                        yield return partner;
                    }
                }
            }
            while (partnersPage?.OdataNextLink != null &&
                   (partnersPage = await _client.Policies.CrossTenantAccessPolicy.Partners.WithUrl(partnersPage.OdataNextLink).GetAsync()) != null);
        }

        public async Task<DateTime?> GetPolicyLastModificationDate(string policyId)
        {
            var filter = $"targetResources/any(c:c/id eq '{policyId}') and result eq 'success' and category eq 'Policy'";
            return await GetLastModificationDateFromAuditLogsAsync(filter);
        }
        
        public async IAsyncEnumerable<NamedLocation> GetNamedLocationsAsync()
        {
            var locationsPage = await _client.Identity.ConditionalAccess.NamedLocations.GetAsync();

            do
            {
                if (locationsPage?.Value != null)
                {
                    foreach (var location in locationsPage.Value)
                    {
                        yield return location;
                    }
                }
            }
            while (locationsPage?.OdataNextLink != null &&
                   (locationsPage = await _client.Identity.ConditionalAccess.NamedLocations
                                            .WithUrl(locationsPage.OdataNextLink)
                                            .GetAsync()) != null);
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

        public async Task<User> GetUserByIdAsync(string userId, IEnumerable<string> selectProperties = null)
        {
            return await _client.Users[userId].GetAsync(config =>
            {
                if (selectProperties != null && selectProperties.Any())
                {
                    config.QueryParameters.Select = selectProperties.ToArray();
                }
            });
        }

        public async IAsyncEnumerable<DirectoryObject> GetGroupDirectMembersAsync(string groupId)
        {
            var membersPage = await _client.Groups[groupId].Members.GetAsync(config =>
            {
                config.QueryParameters.Select = new[] { "id", "displayName", "userPrincipalName", "userType" };
            });

            do
            {
                if (membersPage?.Value != null)
                {
                    foreach (var member in membersPage.Value)
                    {
                        yield return member;
                    }
                }
            }
            while (membersPage?.OdataNextLink != null &&
                   (membersPage = await _client.Groups[groupId].Members.WithUrl(membersPage.OdataNextLink).GetAsync()) != null);
        }

        public async IAsyncEnumerable<User> GetGroupTransitiveMembersAsync(string groupId)
        {
            var users = await _client.Groups[groupId].TransitiveMembers.GetAsync();

            do
            {
                foreach (var user in users.Value.OfType<User>())
                {
                    yield return await _client.Users[user.Id].GetAsync();
                }
            }
            while (users?.OdataNextLink != null &&
                    (users = await _client.Groups[groupId].TransitiveMembers.WithUrl(users.OdataNextLink).GetAsync()) != null);

        }

        public async IAsyncEnumerable<User> GetAllUsersAsync(IEnumerable<string> selectProperties = null, string filter = null)
        {
            var defaultProps = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
                "id",
                "userPrincipalName",
                "userType",
                "onPremisesImmutableId",
                "externalUserState",
                "externalUserStateChangeDateTime",
                "createdDateTime",
                "lastPasswordChangeDateTime",
                "passwordPolicies"
            };

            if (selectProperties != null)
            {
                foreach (var prop in selectProperties) defaultProps.Add(prop);
            }

            var usersPage = await _client.Users.GetAsync(config =>
            {
                config.QueryParameters.Select = defaultProps.ToArray();
                if (!string.IsNullOrWhiteSpace(filter))
                {
                    config.QueryParameters.Filter = filter;
                }
            });

            do
            {
                if (usersPage?.Value != null)
                {
                    foreach (var user in usersPage.Value)
                    {
                        yield return user;
                    }
                }
            }
            while (usersPage?.OdataNextLink != null && (usersPage = await _client.Users.WithUrl(usersPage.OdataNextLink).GetAsync()) != null);
        }

        public async IAsyncEnumerable<DirectoryObject> GetUserMembershipAsync(string userId)
        {
            var membershipPage = await _client.Users[userId].MemberOf.GetAsync(config =>
            {
                config.QueryParameters.Select = new[] { "id", "displayName", "roleTemplateId" }; 
            });

            do
            {
                if (membershipPage?.Value != null)
                {
                    foreach (var memberOf in membershipPage.Value)
                    {
                        yield return memberOf;
                    }
                }
            }
            while (membershipPage?.OdataNextLink != null &&
                   (membershipPage = await _client.Users[userId].MemberOf.WithUrl(membershipPage.OdataNextLink).GetAsync()) != null);
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

        private async Task<DateTime?> GetLastModificationDateFromAuditLogsAsync(string filter)
        {
            var auditResponse = await _client.AuditLogs.DirectoryAudits
                .GetAsync(requestConfiguration =>
                {
                    requestConfiguration.QueryParameters.Filter = filter;
                    requestConfiguration.QueryParameters.Orderby = new[] { "activityDateTime desc" };
                    requestConfiguration.QueryParameters.Top = 1;
                    requestConfiguration.QueryParameters.Select = new[] { "activityDateTime" };
                });

            return auditResponse?.Value?.FirstOrDefault()?.ActivityDateTime?.UtcDateTime;
        }

        public async IAsyncEnumerable<ServicePrincipal> GetAllServicePrincipalsAsync()
        {
            var servicePrincipalsPage = await _client.ServicePrincipals.GetAsync(config =>
            {
                config.QueryParameters.Select = new[] {
                    "id", "appId", "displayName", "appOwnerOrganizationId"
                };
            });

            do
            {
                if (servicePrincipalsPage?.Value != null)
                {
                    foreach (var sp in servicePrincipalsPage.Value)
                    {
                        yield return sp;
                    }
                }
            }
            while (servicePrincipalsPage?.OdataNextLink != null &&
                   (servicePrincipalsPage = await _client.ServicePrincipals.WithUrl(servicePrincipalsPage.OdataNextLink).GetAsync()) != null);
        }

        public async IAsyncEnumerable<OAuth2PermissionGrant> GetAllOAuth2PermissionGrantsAsync()
        {
            var grantsPage = await _client.Oauth2PermissionGrants.GetAsync(config =>
            {
                config.QueryParameters.Select = new[] {
                    "id", "clientId", "consentType", "principalId", "resourceId", "scope", "expiryTime"
                };
            });

            do
            {
                if (grantsPage?.Value != null)
                {
                    foreach (var grant in grantsPage.Value)
                    {
                        yield return grant;
                    }
                }
            }
            while (grantsPage?.OdataNextLink != null &&
                   (grantsPage = await _client.Oauth2PermissionGrants.WithUrl(grantsPage.OdataNextLink).GetAsync()) != null);
        }

        public async Task<IReadOnlyList<AppRole>> GetServicePrincipalAppRolesAsync(string servicePrincipalId)
        {
            try
            {
                var sp = await _client.ServicePrincipals[servicePrincipalId].GetAsync(config =>
                {
                    config.QueryParameters.Select = new[] { "id", "appRoles" };
                });

                return sp.AppRoles;
            }
            catch (Exception ex)
            {
                Trace.TraceError($"ServicePrincipal id: {servicePrincipalId} not found. Error: {ex}");
                return null;
            }
        }

        public async IAsyncEnumerable<AppRoleAssignment> GetAppRoleAssignmentsToServicePrincipalAsync(string servicePrincipalId)
        {
            var assignmentsPage = await _client.ServicePrincipals[servicePrincipalId].AppRoleAssignments.GetAsync(config =>
            {
                config.QueryParameters.Select = new[] {
                "id", "appRoleId", "principalType", "resourceDisplayName", "resourceId"
                };
            });

            do
            {
                if (assignmentsPage?.Value != null)
                {
                    foreach (var assignment in assignmentsPage.Value)
                    {
                        yield return assignment;
                    }
                }
            }
            while (assignmentsPage?.OdataNextLink != null &&
                   (assignmentsPage = await _client.ServicePrincipals[servicePrincipalId].AppRoleAssignedTo
                                            .WithUrl(assignmentsPage.OdataNextLink)
                                            .GetAsync()) != null);
        }

        public async IAsyncEnumerable<DirectoryObject> GetServicePrincipalMembershipAsync(string servicePrincipalId)
        {
            var membershipPage = await _client.ServicePrincipals[servicePrincipalId].MemberOf.GetAsync(config =>
            {
                config.QueryParameters.Select = new[] { "id", "displayName", "roleTemplateId" };
            });

            do
            {
                if (membershipPage?.Value != null)
                {
                    foreach (var memberOf in membershipPage.Value)
                    {
                        yield return memberOf;
                    }
                }
            }
            while (membershipPage?.OdataNextLink != null &&
                   (membershipPage = await _client.ServicePrincipals[servicePrincipalId].MemberOf
                                            .WithUrl(membershipPage.OdataNextLink)
                                            .GetAsync()) != null);
        }
    }
}
