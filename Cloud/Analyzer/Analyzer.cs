//
// Copyright (c) Vincent LE TOUX for Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Cloud.Credentials;
using PingCastle.Cloud.Data;
using PingCastle.Cloud.PublicServices;
using PingCastle.Cloud.RESTServices;
using PingCastle.Cloud.RESTServices.Azure;
using PingCastle.Cloud.RESTServices.O365;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Mail;
using System.Reflection;
using PingCastle.Cloud.Tokens;
using System.Threading.Tasks;
using PingCastle.Cloud.Common;
using PingCastle.Rules;
using Microsoft.Graph.Beta.Models;
using PingCastle.Cloud.MsGraph;
using System.Collections.Concurrent;
using PingCastle.misc;
using PingCastle.UserInterface;

namespace PingCastle.Cloud.Analyzer
{
    public class Analyzer
    {
        HealthCheckCloudData data;
        private IAzureCredential credential;
        const int MaxParallel = 20;

        private static readonly List<string> EnabledMfa = new List<string>() { "Enabled" };
        private static readonly List<string> DisabledMfa = new List<string>() { "Disabled" };
        private static readonly List<string> EnforcedMfa = new List<string>() { "Enforced" };
        private readonly IUserInterface _ui;

        public Analyzer(IAzureCredential credential)
        {
            this.credential = credential;
            _ui = UserInterfaceFactory.GetUserInterface();
        }


        public async Task<HealthCheckCloudData> Analyze()
        {
            try
            {
                DisplayAdvancement("Starting");
                HttpClientHelper.LogComment = "Analyze start";
                data = new HealthCheckCloudData();
                data.GenerationDate = DateTime.Now;
                Version version = Assembly.GetExecutingAssembly().GetName().Version;
                data.EngineVersion = version.ToString(4);
#if DEBUG
                data.EngineVersion += " Beta";
#endif

                DisplayAdvancement("Authenticate");

                Token AzureToken = await credential.GetToken<MsGraphApiFacade>();

                data.TenantId = credential.Tenantid;
                var jwt = AzureToken.ToJwtToken();
                if (!string.IsNullOrEmpty(jwt.onprem_sid))
                {
                    var sidpart = jwt.onprem_sid.Split('-');
                    if (sidpart.Length > 3)
                    {
                        sidpart = sidpart.Take(sidpart.Count() - 1).ToArray();
                        data.OnPremiseDomainSid = string.Join("-", sidpart);
                    }
                }
                // just in case the tenant name cannot be retrieved from domain analysis
                if (!string.IsNullOrEmpty(jwt.unique_name))
                {
                    var sp = jwt.unique_name.Split('@');
                    if (sp.Length > 1)
                        data.TenantName = sp[1];
                }

                await RunTaskAsync("DNS Domains", AnalyzeDNSDomains);

                RunTask("Known tenant", AnalyzeKnownTenant);

                DisplayAdvancement("Get Configuration");

                if (!string.IsNullOrEmpty(data.TenantName))
                {
                    var openId = await PublicService.GetOpenIDConfiguration(data.TenantName);

                    //data.TenantId = openId.issuer.Replace("https://sts.windows.net/", "").Replace("/", "");
                    data.Region = openId.tenant_region_scope;
                }
                await RunTaskAsync("Company Info", AnalyzeCompanyInfo);
                if (!data.UsersPermissionToReadOtherUsersEnabled)
                {
                    DisplayAdvancement("UsersPermissionToReadOtherUsersEnabled is False. Only an admin will be able to analyze users & admins");
                }

                await RunTaskAsync("Policies", AnalyzePolicies);

                RunTask("AD Connect", AnalyzeADConnect);

                await RunTaskAsync("Applications and permissions", AnalyzeApplications);

                var adminCache = await RunTaskAsync("Roles", AnalyzeAdminRoles);

                await RunTaskAsync("Users", () => AnalyzeAllUsers(adminCache));

                RunTask("Foreign domains", AnalyseForeignDomains);

                RunTask("Outlook online", AnalyzeOutlookOnline);

                DisplayAdvancement("Computing risks");
                var rules = new RuleSet<HealthCheckCloudData>();
                data.RiskRules = new List<HealthCheckCloudDataRiskRule>();
                foreach (var rule in rules.ComputeRiskRules(data))
                {
                    HealthCheckCloudDataRiskRule risk = new HealthCheckCloudDataRiskRule();
                    risk.Points = rule.Points;
                    risk.RiskId = rule.RiskId;
                    risk.Rationale = rule.Rationale;
                    risk.Details = rule.Details;
                    risk.ExtraDetails = rule.ExtraDetails;
                    data.RiskRules.Add(risk);
                }

                DisplayAdvancement("Done");
                return data;
            }
            catch (Exception ex)
            {
                Trace.WriteLine(ex.Message);
                Trace.WriteLine(ex.StackTrace);
                throw;
            }
        }

        void RunTask(string display, Action action)
        {
            DisplayAdvancement(display);
            HttpClientHelper.LogComment = "Task:" + display;
            try
            {
                action();
                Trace.TraceInformation($"{DateTime.Now}: Task {display} has been successful completed");
            }
            catch (Exception ex)
            {
                Trace.TraceError(ex.ToString());
                ShowLastError(display, ex);
            }
            HttpClientHelper.LogComment = null;
        }

        async Task RunTaskAsync(string display, Func<Task> action)
        {
            DisplayAdvancement(display);
            HttpClientHelper.LogComment = "Task:" + display;
            try
            {
                await action();
                Trace.TraceInformation($"{DateTime.Now}: Task {display} has been successful completed");
            }
            catch (Exception ex)
            {
                Trace.TraceError(ex.ToString());
                ShowLastError(display, ex);
            }
            HttpClientHelper.LogComment = null;
        }

        async Task<T> RunTaskAsync<T>(string display, Func<Task<T>> action)
        {
            DisplayAdvancement(display);
            HttpClientHelper.LogComment = "Task:" + display;
            try
            {
                var result = await action();
                Trace.TraceInformation($"{DateTime.Now}: Task {display} has been successful completed");
                return result;
            }
            catch (Exception ex)
            {
                Trace.TraceError(ex.ToString());
                ShowLastError(display, ex);
            }
            HttpClientHelper.LogComment = null;

            return default;
        }

        private void ShowLastError(string display, Exception ex)
        {
            var e = ex;
            string lastMessage = null;
            while (e != null)
            {
                lastMessage = e.Message;
                e = e.InnerException;
            }
            DisplayAdvancementWarning("Exception when doing " + display);
            DisplayAdvancementWarning(lastMessage);
            DisplayAdvancementWarning("Continuing");
        }

        private async Task AnalyzeApplications()
        {
            var graph = GraphApiClientFactory.Create(credential);
            var permissions = await graph.GetAllOAuth2PermissionGrantsAsync().ToListAsync();
            var appRolesCache = new ConcurrentDictionary<string, IReadOnlyDictionary<string, AppRole>>();
            var applications = new ConcurrentBag<HealthCheckCloudDataApplication>();

            var allTasks = new List<Task>();
            await foreach (var sp in graph.GetAllServicePrincipalsAsync())
            {
                allTasks.Add(Task.Run(() => AddApplicationData(graph, permissions, appRolesCache, applications, sp)));
            }
            DisplayAdvancement($"{allTasks.Count} applications found");
            await Task.WhenAll(allTasks);

            data.Applications = new List<HealthCheckCloudDataApplication>(applications);

            var nonEmptyAppsCount = data.Applications
                .Where(x => x.ApplicationPermissions.Count > 0 || x.DelegatedPermissions.Count > 0 || x.MemberOf.Count > 0)
                .Count();
            DisplayAdvancement($"{nonEmptyAppsCount} applications found with permissions assigned and having roles");
        }

        private async Task AddApplicationData(IGraphApiClient graph,
            List<OAuth2PermissionGrant> permissions,
            ConcurrentDictionary<string, IReadOnlyDictionary<string, AppRole>> appRolesCache,
            ConcurrentBag<HealthCheckCloudDataApplication> applications,
            ServicePrincipal sp)
        {
            var appData = new HealthCheckCloudDataApplication
            {
                objectId = sp.Id,
                appDisplayName = sp.DisplayName,
                appOwnerTenantId = sp.AppOwnerOrganizationId?.ToString(),
                appId = sp.AppId,
                DelegatedPermissions = new List<HealthCheckCloudDataApplicationOAuth2PermissionGrant>(),
                MemberOf = new List<HealthCheckCloudDataApplicationMemberOf>(),
                ApplicationPermissions = new List<HealthCheckCloudDataApplicationRoleAssignedTo>(),
            };
            applications.Add(appData);

            var delegatedPermissions = permissions.Where(x => x.ClientId == sp.Id);
            foreach (var permission in delegatedPermissions)
            {
                foreach (var scope in permission.Scope.Split(' '))
                {
                    if (string.IsNullOrEmpty(scope))
                        continue;
                    appData.DelegatedPermissions.Add(new HealthCheckCloudDataApplicationOAuth2PermissionGrant()
                    {
                        permission = scope,
                        resourceId = permission.ResourceId,
                        consentType = permission.ConsentType,
                        principalId = permission.PrincipalId,
                    });
                }
            }

            try
            {
                await foreach (var roleAssignment in graph.GetAppRoleAssignmentsToServicePrincipalAsync(sp.Id))
                {
                    var permission = new HealthCheckCloudDataApplicationRoleAssignedTo
                    {
                        resourceDisplayName = roleAssignment.ResourceDisplayName,
                        resourceId = roleAssignment.ResourceId?.ToString(),
                        permissionId = roleAssignment.AppRoleId?.ToString(),
                        principalType = roleAssignment.PrincipalType,
                    };

                    if (permission.principalType == "ServicePrincipal")
                    {
                        if (!appRolesCache.TryGetValue(permission.resourceId, out var appRoles))
                        {
                            var roles = await graph.GetServicePrincipalAppRolesAsync(permission.resourceId);
                            appRoles = roles.ToDictionary(k => k.Id?.ToString());
                            appRolesCache[permission.resourceId] = appRoles;
                        }

                        if (appRoles.TryGetValue(permission.permissionId, out var appRole))
                        {
                            permission.permission = appRole.Value;
                        }
                    }

                    appData.ApplicationPermissions.Add(permission);
                }

                await foreach (var member in graph.GetServicePrincipalMembershipAsync(sp.Id))
                {
                    appData.MemberOf.Add(new HealthCheckCloudDataApplicationMemberOf
                    {
                        displayName = GetDirectoryObjectDisplayName(member),
                        roleTemplateId = member is DirectoryRole role ? role.RoleTemplateId : null,
                    });
                }
            }
            catch (Exception ex)
            {
                Trace.WriteLine("Exception when analyzing " + sp.Id);
                Trace.WriteLine(ex.ToString());
            }
        }

        private string GetDirectoryObjectDisplayName(DirectoryObject directoryObject)
        {
            if (directoryObject == null) return null;

            return directoryObject switch
            {
                User user => user.DisplayName,
                Group group => group.DisplayName,
                DirectoryRole role => role.DisplayName,
                AdministrativeUnit adminUnit => adminUnit.DisplayName,
                Device device => device.DisplayName,
                Organization org => org.DisplayName,
                ServicePrincipal sp => sp.DisplayName, 
                OrgContact contact => contact.DisplayName
            };
        }

        private void AnalyzeADConnect()
        {
            var graph = new AzureADConnectApi(credential);
            var p = graph.ADConnectStatus();
            data.AzureADConnectDirSyncConfigured = p.dirSyncConfigured;
            data.AzureADConnectDirSyncEnabled = p.dirSyncEnabled;
            data.AzureADConnectFederatedDomainCount = p.federatedDomainCount;
            data.AzureADConnectNumberOfHoursFromLastSync = p.numberOfHoursFromLastSync;
            data.AzureADConnectPassThroughAuthenticationEnabled = p.passThroughAuthenticationEnabled;
            data.AzureADConnectSeamlessSingleSignOnEnabled = p.seamlessSingleSignOnEnabled;
            data.AzureADConnectVerifiedCustomDomainCount = p.verifiedCustomDomainCount;
            data.AzureADConnectVerifiedDomainCount = p.verifiedDomainCount;
        }

        private void AnalyzeKnownTenant()
        {
            data.ExternalTenantInformation = new List<HealthCheckCloudDataTenantInformation>();

            var graph = new ManagementApi(credential);
            var p = graph.ListTenants();
            if (p.responses != null && p.responses.Count > 0)
            {
                foreach (var r in p.responses)
                {
                    foreach (var value in r.content.value)
                    {
                        data.ExternalTenantInformation.Add(new HealthCheckCloudDataTenantInformation()
                        {
                            TenantID = value.tenantId,
                            TenantCategory = value.tenantCategory,
                            Name = value.displayName,
                            CountryCode = value.countryCode,
                            Domains = value.domains,
                        });

                    }
                }
                if (string.IsNullOrEmpty(data.TenantName))
                {
                    var x1 = p.responses[0].content.value
                        .Where(x => x.tenantId == data.TenantId).FirstOrDefault();
                    if (x1.domains != null)
                        data.TenantName = x1.domains
                            .Where(x => x.EndsWith(".onmicrosoft.com") && !x.EndsWith(".mail.onmicrosoft.com"))
                            .FirstOrDefault();
                }
            }
        }

        private async Task AnalyzePolicies()
        {
            var graph = GraphApiClientFactory.Create(credential);
            var allTasks = new List<Task>
            {
                Task.Run(() => FillCrossTenantPolicies(graph)),
                Task.Run(() => FillNetworkPolicies(graph)),
                Task.Run(() => FillAuthorizationPolicy(graph)),
            };

            await Task.WhenAll(allTasks);
        }

        private async Task FillAuthorizationPolicy(IGraphApiClient graph)
        {
            var authorizationPolicy = await graph.GetAuthorizationPolicyAsync();
            if (authorizationPolicy != null)
            {
                if (authorizationPolicy.GuestUserRoleId.HasValue)
                    data.PolicyGuestUserRoleId = authorizationPolicy.GuestUserRoleId.Value.ToString();
                data.PolicyAllowEmailVerifiedUsersToJoinOrganization = authorizationPolicy.AllowEmailVerifiedUsersToJoinOrganization;
            }
        }

        private async Task FillNetworkPolicies(IGraphApiClient graph)
        {
            data.NetworkPolicies = new List<HealthCheckCloudDataNetworkPolicy>();

            await foreach (var location in graph.GetNamedLocationsAsync())
            {
                if (location is IpNamedLocation ipLoc)
                {
                    foreach (var range in ipLoc.IpRanges)
                    {
                        string cidrAddress = null;
                        if (range is IPv4CidrRange ipv4Range)
                        {
                            cidrAddress = ipv4Range.CidrAddress;
                        }
                        else if (range is IPv6CidrRange ipv6Range)
                        {
                            cidrAddress = ipv6Range.CidrAddress;
                        }

                        if (!string.IsNullOrEmpty(cidrAddress))
                        {
                            data.NetworkPolicies.Add(new HealthCheckCloudDataNetworkPolicy()
                            {
                                Name = ipLoc.DisplayName,
                                Definition = cidrAddress,
                                Type = "CIDR", 
                                Trusted = ipLoc.IsTrusted ?? false,
                                ApplyToUnknownCountry = false // Not applicable to IP
                            });
                        }
                    }
                }
                else if (location is CountryNamedLocation countryLoc)
                {
                    foreach (var countryCode in countryLoc.CountriesAndRegions)
                    {
                        if (!string.IsNullOrEmpty(countryCode))
                        {
                            data.NetworkPolicies.Add(new HealthCheckCloudDataNetworkPolicy()
                            {
                                Name = countryLoc.DisplayName,
                                Definition = countryCode,
                                Type = "Country",
                                Trusted = false, // Countries don't have a Trusted flag
                                ApplyToUnknownCountry = countryLoc.IncludeUnknownCountriesAndRegions ?? false,
                            });
                        }
                    }
                }
            }
        }

        private async Task FillCrossTenantPolicies(IGraphApiClient graph)
        {
            var cta = await graph.GetCrossTenantAccessPolicyAsync();
            if (cta == null)
                return;

            var lastModified = await graph.GetPolicyLastModificationDate(cta.Id);

            data.CrossTenantPolicies = new List<HealthCheckCloudDataCrossTenantPolicy>();
            await foreach (var partner in graph.GetPartnerCrossTenantAccessPoliciesAsync())
            {
                if (string.IsNullOrEmpty(partner?.TenantId)) continue; 

                var b2bIn = partner.B2bCollaborationInbound;
                var b2bOut = partner.B2bCollaborationOutbound;
                var dcIn = partner.B2bDirectConnectInbound;
                var dcOut = partner.B2bDirectConnectOutbound;

                var ctp = new HealthCheckCloudDataCrossTenantPolicy()
                {
                    TenantId = partner.TenantId,
                    lastModified = lastModified?.ToString(), 
                    AllowB2BFrom = IsAllowAccess(b2bIn?.UsersAndGroups?.AccessType),
                    AllowB2BTo = IsAllowAccess(b2bOut?.UsersAndGroups?.AccessType),
                    AllowNativeFederationFrom = IsAllowAccess(dcIn?.UsersAndGroups?.AccessType),
                    AllowNativeFederationTo = IsAllowAccess(dcOut?.UsersAndGroups?.AccessType),
                };
                data.CrossTenantPolicies.Add(ctp);
            }
        }

        private bool? IsAllowAccess(CrossTenantAccessPolicyTargetConfigurationAccessType? accessType)
        {
            return accessType switch
            {
                CrossTenantAccessPolicyTargetConfigurationAccessType.Allowed => true,
                CrossTenantAccessPolicyTargetConfigurationAccessType.Blocked => false,
                _ => null
            };
        }

        private async Task AnalyzeAllUsers(IReadOnlyDictionary<string, HealthCheckCloudDataRoleMember> adminCache)
        {
            var appPermissionsToComplete = new Dictionary<string, List<HealthCheckCloudDataApplicationOAuth2PermissionGrant>>();
            if (data.Applications != null)
            {
                foreach (var app in data.Applications)
                {
                    foreach (var delegation in app.DelegatedPermissions)
                    {
                        if (!string.IsNullOrWhiteSpace(delegation.principalId))
                        {
                            if (!appPermissionsToComplete.ContainsKey(delegation.principalId))
                                appPermissionsToComplete[delegation.principalId] = new List<HealthCheckCloudDataApplicationOAuth2PermissionGrant>();
                            appPermissionsToComplete[delegation.principalId].Add(delegation);
                        }
                    }
                }
            }

            Dictionary<string, int> ForeignDomainsGuest = new Dictionary<string, int>();
            Dictionary<string, int> ForeignDomainsMember = new Dictionary<string, int>();
            var now = DateTime.Now;

            data.UsersPasswordNeverExpires = new List<HealthCheckCloudDataUser>();
            data.UsersInactive = new List<HealthCheckCloudDataUser>();
            data.OldInvitations = new List<HealthCheckCloudDataUser>();
            data.NumberOfUsers = 0;

            var graph = GraphApiClientFactory.Create(credential);
            await foreach (var user in graph.GetAllUsersAsync())
            {
                data.NumberOfUsers++;

                if ((data.NumberOfUsers % 500) == 0)
                {
                    _ui.AddText("+");
                    Trace.Write("+");
                }

                var userType = user.UserType?.ToString();

                if (user.Id != null && adminCache?.Count > 0)
                {
                    if (adminCache.TryGetValue(user.Id, out var member))
                    {
                        member.WhenCreated = user.CreatedDateTime?.UtcDateTime;
                        member.LastPasswordChangeTimestamp = user.LastPasswordChangeDateTime?.UtcDateTime;
                        member.PasswordNeverExpires = user.PasswordPolicies?.ToString().Contains("DisablePasswordExpiration") ?? false;
                        member.HasImmutableId = user.OnPremisesImmutableId != null;
                    }
                    if (appPermissionsToComplete.TryGetValue(user.Id, out var permissions))
                    {
                        foreach (var permission in permissions)
                        {
                            permission.principalDisplayName = user.UserPrincipalName;
                        }
                    }
                }

                int index = user.UserPrincipalName.IndexOf("#EXT#@");
                if (userType == "Guest" && index > 0)
                {
                    data.NumberofGuests++;
                    int index2 = user.UserPrincipalName.LastIndexOf("_", index);
                    if (index2 > 0)
                    {
                        string domain = user.UserPrincipalName.Substring(index2 + 1, index - index2 - 1).ToLowerInvariant();
                        if (!ForeignDomainsGuest.ContainsKey(domain))
                            ForeignDomainsGuest[domain] = 0;
                        ForeignDomainsGuest[domain]++;
                    }
                    if (user.ExternalUserState == "PendingAcceptance")
                    {
                        if (DateTimeOffset.TryParse(user.ExternalUserStateChangeDateTime, out var userStateChangedOn) && userStateChangedOn.UtcDateTime.AddMonths(1) < now)
                        {
                            data.OldInvitations.Add(new HealthCheckCloudDataUser()
                            {
                                ObjectId = user.Id,
                                UserPrincipalName = user.UserPrincipalName,
                                WhenCreated = user.CreatedDateTime?.UtcDateTime,
                                LastPasswordChangeTimestamp = user.LastPasswordChangeDateTime?.UtcDateTime,
                                PasswordNeverExpires = user.PasswordPolicies?.Contains("DisablePasswordExpiration"),
                                HasImmutableId = user.OnPremisesImmutableId != null,
                            });
                        }
                    }
                }
                else
                {
                    data.NumberofMembers++;
                    if (index > 0)
                    {
                        data.NumberofExternalMembers++;
                        int index2 = user.UserPrincipalName.LastIndexOf("_", index);
                        if (index2 > 0)
                        {
                            string domain = user.UserPrincipalName.Substring(index2 + 1, index - index2 - 1).ToLowerInvariant();
                            if (!ForeignDomainsMember.ContainsKey(domain))
                                ForeignDomainsMember[domain] = 0;
                            ForeignDomainsMember[domain]++;
                        }
                    }
                    else
                    {
                        data.NumberofInternalMembers++;
                        if (!string.IsNullOrEmpty(user.OnPremisesImmutableId))
                        {
                            data.NumberofSyncInternalMembers++;
                        }
                        else
                        {
                            data.NumberofPureAureInternalMembers++;
                        }
                    }
                }
            }


            _ui.DisplayMessage("");

            var fd = new Dictionary<string, HealthCheckCloudDataForeignDomains>();
            foreach (var domain in ForeignDomainsGuest.Keys)
            {
                var d = new HealthCheckCloudDataForeignDomains();
                d.Domain = domain;
                d.GuestsCount = ForeignDomainsGuest[domain];
                fd[domain] = d;
            }
            foreach (var domain in ForeignDomainsMember.Keys)
            {
                if (!fd.ContainsKey(domain))
                {
                    fd[domain] = new HealthCheckCloudDataForeignDomains();
                    fd[domain].Domain = domain;
                }
                fd[domain].MemberCount = ForeignDomainsMember[domain];
            }
            data.ForeignDomains = new List<HealthCheckCloudDataForeignDomains>(fd.Values);

        }

        private async Task<IReadOnlyDictionary<string, HealthCheckCloudDataRoleMember>> AnalyzeAdminRoles()
        {
            string[] queryProperties = new string[]
            {
                "EmailAddress",
                "ObjectId",
                "DisplayName",
                "IsLicensed",
                "LastDirSyncTime",
                "OverallProvisioningStatus",
                "RoleMemberType",
                "ValidationStatus",
            };
            var cache = new ConcurrentDictionary<string, HealthCheckCloudDataRoleMember>();
            var api = GraphApiClientFactory.Create(credential);

            var templates = api.GetRoleTemplatesAsync();
            var templatesById = await templates.ToDictionaryAsync(k => k.Id);
            var assignedTemplatesIds = new ConcurrentDictionary<string, byte>();
            var allRoles = new ConcurrentBag<HealthCheckCloudDataRole>();


            var tasks = new List<Task>();
            await foreach (var role in api.GetRolesAsync())
            {
                tasks.Add(Task.Run(() => AddRoleAsync(cache, api, templatesById, allRoles, role, assignedTemplatesIds)));
            }

            await Task.WhenAll(tasks);

            AddUnassignedRoles(templatesById.Values.Where(t=> !assignedTemplatesIds.ContainsKey(t.Id)), allRoles);

            data.Roles = new List<HealthCheckCloudDataRole>(allRoles);

            await FillMembersMfaStatus(api);

            return cache;
        }

        private void AddUnassignedRoles(IEnumerable<DirectoryRoleTemplate> templates, ConcurrentBag<HealthCheckCloudDataRole> allRoles)
        {
            foreach (var template in templates)
            {
                allRoles.Add(
                    new HealthCheckCloudDataRole()
                    {
                        ObjectId = new Guid(template.Id),
                        Name = template.DisplayName,
                        IsEnabled = false,
                        IsSystem = true,
                        Description = template.Description,
                        members = new List<HealthCheckCloudDataRoleMember>(),
                    });
            }
        }

        private async Task AddRoleAsync(ConcurrentDictionary<string,
            HealthCheckCloudDataRoleMember> cache,
            IGraphApiClient api,
            Dictionary<string, DirectoryRoleTemplate> templatesById,
            ConcurrentBag<HealthCheckCloudDataRole> allRoles,
            DirectoryRole role,
            ConcurrentDictionary<string, byte> assignedTemplatesIds)
        {
            try
            {
                var r = new HealthCheckCloudDataRole()
                {
                    ObjectId = new Guid(role.Id),
                    Name = role.DisplayName,
                    IsEnabled = true,
                    Description = role.Description,
                    members = new List<HealthCheckCloudDataRoleMember>(),
                };

                allRoles.Add(r);

                r.IsSystem = templatesById.ContainsKey(role.RoleTemplateId);

                assignedTemplatesIds.GetOrAdd(role.RoleTemplateId, 0);

                foreach (var member in role.Members.OfType<User>())
                {
                    r.NumMembers++;

                    var hcMember = cache.GetOrAdd(member.Id, new HealthCheckCloudDataRoleMember()
                    {
                        EmailAddress = string.IsNullOrEmpty(member.Mail) ? member.UserPrincipalName : member.Mail,
                        ObjectId = member.Id,
                        DisplayName = member.DisplayName,
                        IsLicensed = member.AssignedLicenses.Any(),
                        LastDirSyncTime = member.OnPremisesLastSyncDateTime?.UtcDateTime,
                        RoleMemberType = "User",
                        OverallProvisioningStatus = await CalculateOverallProvisioningStatus(api, member.Id)
                    });

                    r.members.Add(hcMember);
                }
            }
            catch (Exception ex)
            {
                Trace.WriteLine("Exception when analyzing " + role.Id);
                Trace.WriteLine(ex.ToString());
            }
        }

        private async Task FillMembersMfaStatus(IGraphApiClient api)
        {
            var registrationDetails = api.GetUserRegistrationDetailsAsync();
            var detailsByUser = await registrationDetails.ToDictionaryAsync(k => k.Id);

            foreach (var role in data.Roles.Where(x => x.NumMembers > 0))
            {
                foreach (var member in role.members)
                {
                    if (detailsByUser.TryGetValue(member.ObjectId, out var details))
                    {
                        var status = EnabledMfa;
                        if (!details.IsMfaRegistered.GetValueOrDefault())
                        {
                            status = DisabledMfa;
                            role.NumNoMFA++;
                        }
                        else if (details.IsMfaCapable.GetValueOrDefault())
                        {
                            status = EnabledMfa;
                        }

                        member.MFAStatus = status;
                    }
                }
            }
        }

        private async Task<string> CalculateOverallProvisioningStatus(IGraphApiClient api, string memberId)
        {
            var licenses = await api.GetUserLicensesAsync(memberId);
            var provisionedPlans = licenses?.SelectMany(l=> l.ServicePlans);

            if (provisionedPlans == null || !provisionedPlans.Any())
                return "None";

            if (provisionedPlans.Any(sp => sp.ProvisioningStatus == "Error"))
                return "Error";

            if (provisionedPlans.Any(sp => sp.ProvisioningStatus == "PendingProvisioning" ||
                                       sp.ProvisioningStatus == "PendingActivation"))
                return "PendingProvisioning";

            if (provisionedPlans.All(sp => sp.ProvisioningStatus == "Success"))
                return "Success";

            if (provisionedPlans.All(sp => sp.ProvisioningStatus == "Disabled"))
                return "Disabled";

            return "Unknown"; // statuses are mixed
        }

        private async Task AnalyzeDNSDomains()
        {
            var api = GraphApiClientFactory.Create(credential);

            var domains = await api.GetDomainsAsync();
            if (domains.Any())
            {
                data.Domains = new List<HealthCheckCloudDataDomain>();
                foreach (var d in domains)
                {
                    if (d.IsInitial.GetValueOrDefault())
                    {
                        Trace.WriteLine($"Update tenant name from initial domain: {d.Id}");
                        data.TenantName = d.Id;
                    }

                    IReadOnlyList<DomainDnsRecord> dnsRecords = null;

                    var isVerified = d.IsVerified.GetValueOrDefault();
                    if (isVerified)
                    {
                        dnsRecords = await api.GetDomainDnsRecordsAsync(d.Id);
                    }

                    var isRecordsExists = dnsRecords?.Any() ?? false;

                    data.Domains.Add(new HealthCheckCloudDataDomain()
                    {
                        Authentication = d.AuthenticationType,
                        Capabilities = d.SupportedServices.Any() ? string.Join(",", d.SupportedServices) : "None",
                        IsDefault = d.IsDefault.GetValueOrDefault(),
                        IsInitial = d.IsInitial.GetValueOrDefault(),
                        Name = d.Id,
                        RootDomain = d.RootDomain?.Id,
                        Status = isVerified ? "Verified" : "Unverified",
                        VerificationMethod = isVerified && isRecordsExists ? $"DnsRecord: {string.Join(",", dnsRecords.Select(r=> r.SupportedService).Distinct())}" : "",
                    });
                }
            }
        }

        private async Task AnalyzeCompanyInfo()
        {
            var graphApi = GraphApiClientFactory.Create(credential);
            var ci = await graphApi.GetCompanyInfoAsync();
            var ap = await graphApi.GetAuthorizationPolicyAsync();
            var onPremSync = await graphApi.GetOnPremisesDirectorySynchronizationAsync();

            data.ProvisionDisplayName = ci.DisplayName;
            data.ProvisionStreet = ci.Street;
            data.ProvisionCity = ci.City;
            data.ProvisionPostalCode = ci.PostalCode;
            data.ProvisionCountry = ci.Country;
            data.ProvisionState = ci.State;
            data.ProvisionTelephoneNumber = ci.BusinessPhones.FirstOrDefault();
            data.ProvisionCountryLetterCode = ci.CountryLetterCode;
            data.ProvisionInitialDomain = ci.VerifiedDomains.First(d => d.IsInitial.GetValueOrDefault()).Name;
            if (ci.OnPremisesLastSyncDateTime.HasValue)
                data.ProvisionLastDirSyncTime = ci.OnPremisesLastSyncDateTime.Value.UtcDateTime;
            if (ci.OnPremisesLastPasswordSyncDateTime.HasValue)
                data.ProvisionLastPasswordSyncTime = ci.OnPremisesLastPasswordSyncDateTime.Value.UtcDateTime;
            if (ap.AllowedToUseSSPR.HasValue)
                data.ProvisionSelfServePasswordResetEnabled = ap.AllowedToUseSSPR.Value;
            data.ProvisionTechnicalNotificationEmails = ci.TechnicalNotificationMails;
            data.ProvisionMarketingNotificationEmails = ci.MarketingNotificationEmails;
            data.ProvisionSecurityComplianceNotificationEmails = ci.SecurityComplianceNotificationMails;
            if (onPremSync.Configuration != null)
            {
                data.ProvisionDirSyncApplicationType = onPremSync.Configuration.ApplicationId;
                data.ProvisionDirSyncClientMachineName = onPremSync.Configuration.CurrentExportData.ClientMachineName;
                data.ProvisionDirSyncClientVersion = onPremSync.Configuration.SynchronizationClientVersion;
                data.ProvisionDirSyncServiceAccount = onPremSync.Configuration.CurrentExportData.ServiceAccount;
            }
            data.ProvisionDirectorySynchronizationStatus = ci.OnPremisesSyncEnabled.GetValueOrDefault() ? "Enabled" : "Disabled";
            data.ProvisionPasswordSynchronizationEnabled = onPremSync.Features.PasswordSyncEnabled;
            if (ci.CreatedDateTime.HasValue)
                data.TenantCreation = ci.CreatedDateTime.Value.UtcDateTime;
            data.UsersPermissionToCreateGroupsEnabled = ap.DefaultUserRolePermissions.AllowedToCreateSecurityGroups.Value;
            data.UsersPermissionToCreateLOBAppsEnabled = ap.DefaultUserRolePermissions.AllowedToCreateApps.Value;
            data.UsersPermissionToReadOtherUsersEnabled = ap.DefaultUserRolePermissions.AllowedToReadOtherUsers.Value;
            data.UsersPermissionToUserConsentToAppEnabled = ap.PermissionGrantPolicyIdsAssignedToDefaultUserRole.Any();
        }

        private void AnalyseForeignDomains()
        {
            if (data.ForeignDomains == null)
                return;
            DisplayAdvancement(data.ForeignDomains.Count + " domain(s) to process");
            Parallel.ForEach(data.ForeignDomains, new ParallelOptions { MaxDegreeOfParallelism = MaxParallel }, (domain) =>
            {
                try
                {
                    var openId = PublicService.GetOpenIDConfiguration(domain.Domain).GetAwaiter().GetResult();
                    domain.Region = openId.tenant_region_scope;
                    domain.TenantID = openId.issuer.Replace("https://sts.windows.net/", "").Replace("/", "");
                }
                catch (Exception ex)
                {
                    Trace.WriteLine("Exception when analyzing " + domain.Domain);
                    Trace.WriteLine(ex.ToString());
                }
            });
        }
        private void AnalyzeOutlookOnline()
        {
            var o365 = new O365Api(credential);
            var mailBoxes = o365.GetMailBoxes();
            data.ForwardingMailboxes = mailBoxes.Where(x => !string.IsNullOrEmpty(x.ForwardingSmtpAddress) && x.ForwardingSmtpAddress.StartsWith("smtp:"))
                .Select(x => new HealthCheckCloudDataForwardingMailboxes
                {
                    PrimarySmtpAddress = x.PrimarySmtpAddress,
                    ForwardingSmtpAddress = x.ForwardingSmtpAddress.Substring(5),
                })
                .Where(x => IsLocalToTenant(x.ForwardingSmtpAddress))
                .ToList();
        }

        private bool IsLocalToTenant(string forwardingSmtpAddress)
        {
            var m = new MailAddress(forwardingSmtpAddress);
            var h = m.Host;
            return data.Domains.Where(x => x.Name == h).Any();
        }

        private void DisplayAdvancement(string data)
        {
            string value = "[" + DateTime.Now.ToLongTimeString() + "] " + data;
            _ui.DisplayMessage(data);
            Trace.WriteLine(value);
        }

        private void DisplayAdvancementWarning(string data)
        {
            string value = "[" + DateTime.Now.ToLongTimeString() + "] " + data;
            _ui.DisplayWarning(data);
            Trace.WriteLine(value);
        }
    }
}
