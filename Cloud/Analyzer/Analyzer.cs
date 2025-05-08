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

namespace PingCastle.Cloud.Analyzer
{
    public class Analyzer
    {
        HealthCheckCloudData data;
        private IAzureCredential credential;

        private static readonly List<string> EnabledMfa = new List<string>() { "Enabled" };
        private static readonly List<string> DisabledMfa = new List<string>() { "Disabled" };
        private static readonly List<string> EnforcedMfa = new List<string>() { "Enforced" };

        public Analyzer(IAzureCredential credential)
        {
            this.credential = credential;
        }
        const int MaxParallel = 20;

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

                Token AzureToken = await credential.GetToken<GraphAPI>();

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

                RunTask("Policies", AnalyzePolicies);

                RunTask("AD Connect", AnalyzeADConnect);

                RunTask("Applications and permissions", AnalyzeApplications);

                var adminCache = await RunTaskAsync("Roles", AnalyzeAdminRoles);

                RunTask("Users", () => { AnalyzeAllUsers(adminCache); });

                RunTask("Foreign domains", AnalyseForeignDomains);

                RunTask("Outlook online", () => AnalyzeOutlookOnline());

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

        private void AnalyzeApplications()
        {
            var g = new GraphAPI(credential);

            var servicePrincipals = g.GetServicePrincipals().ToDictionary(x => x.objectId);
            DisplayAdvancement(servicePrincipals.Count + " applications found");
            var k = g.GetOAuth2PermissionGrants();

            data.Applications = new List<HealthCheckCloudDataApplication>();
            foreach (var app in servicePrincipals.Values)
            {
                var a = new HealthCheckCloudDataApplication
                {
                    objectId = app.objectId,
                    appDisplayName = app.appDisplayName,
                    appOwnerTenantId = app.appOwnerTenantId,
                    appId = app.appId,
                    DelegatedPermissions = new List<HealthCheckCloudDataApplicationOAuth2PermissionGrant>(),
                    MemberOf = new List<HealthCheckCloudDataApplicationMemberOf>(),
                    ApplicationPermissions = new List<HealthCheckCloudDataApplicationRoleAssignedTo>(),
                };
                data.Applications.Add(a);

                var delegatedPermissions = k.Where(x => x.clientId == app.objectId);
                foreach (var permission in delegatedPermissions)
                {
                    /*if (permission.expiryTime < DateTime.Now)
                        continue;*/
                    foreach (var s in permission.scope.Split(' '))
                    {
                        if (string.IsNullOrEmpty(s))
                            continue;
                        a.DelegatedPermissions.Add(new HealthCheckCloudDataApplicationOAuth2PermissionGrant()
                        {
                            permission = s,
                            resourceId = permission.resourceId,
                            consentType = permission.consentType,
                            principalId = permission.principalId,
                        });
                    }
                }
            }
            Parallel.ForEach(data.Applications, new ParallelOptions { MaxDegreeOfParallelism = MaxParallel },
                app =>
                {
                    try
                    {
                        var roles = g.GetAppRoleAssignedTo(app.objectId);
                        var members = g.GetMemberOf(app.objectId);

                        foreach (var role in roles)
                        {
                            app.ApplicationPermissions.Add(new HealthCheckCloudDataApplicationRoleAssignedTo
                            {
                                resourceDisplayName = role.resourceDisplayName,
                                resourceId = role.resourceId,
                                permissionId = role.id,
                                principalType = role.principalType,
                            });
                        }
                        foreach (var member in members)
                        {
                            app.MemberOf.Add(new HealthCheckCloudDataApplicationMemberOf
                            {
                                displayName = member.displayName,
                                roleTemplateId = member.roleTemplateId,
                            });
                        }
                    }
                    catch (Exception ex)
                    {
                        Trace.WriteLine("Exception when analyzing " + app.objectId);
                        Trace.WriteLine(ex.ToString());
                    }
                });

            var refResource = new Dictionary<string, GraphAPI.AzureADObject>();
            foreach (var app in data.Applications)
            {
                foreach (var permission in app.ApplicationPermissions)
                {
                    if (permission.principalType != "ServicePrincipal")
                        continue;
                    if (!refResource.ContainsKey(permission.resourceId))
                    {
                        refResource[permission.resourceId] = g.GetObjectsByObjectIds(permission.resourceId);
                    }
                    var appRoles = refResource[permission.resourceId].appRoles;
                    foreach (var role in appRoles)
                    {
                        if (permission.permissionId == role.id)
                        {
                            permission.permission = role.value;
                        }
                    }
                }
            }
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

        private void AnalyzePolicies()
        {
            var graph = new GraphAPI(credential);
            var p = graph.GetPolicies();

            data.CrossTenantPolicies = new List<HealthCheckCloudDataCrossTenantPolicy>();

            foreach (var policy in p.value)
            {
                if (policy.policyType == 28)
                {
                    ExtractCrossTenantPolicy(policy);
                }
                if (policy.policyType == 7)
                {
                    ExtractPasswordManagementPolicy(policy);
                }
                if (policy.policyType == 6)
                {
                    ExtractNetworkPolicy(policy);
                }
            }

            var ms = new MicrosoftGraph(credential);
            var authorizationPolicies = ms.GetAuthorizationPolicy();
            if (authorizationPolicies != null && authorizationPolicies.Count > 0)
            {
                var authorizationPolicy = authorizationPolicies[0];
                data.PolicyGuestUserRoleId = authorizationPolicy.guestUserRoleId;
                data.PolicyAllowEmailVerifiedUsersToJoinOrganization = authorizationPolicy.allowEmailVerifiedUsersToJoinOrganization;
            }

        }

        private void ExtractNetworkPolicy(GraphAPI.PolicyResponse policy)
        {
            data.NetworkPolicies = new List<HealthCheckCloudDataNetworkPolicy>();

            foreach (var detail in policy.policyDetail)
            {
                var policyDetail = GraphAPI.PolicyDetail.LoadFromString(detail);
                var kn = policyDetail.KnownNetworkPolicies;
                if (kn == null)
                    continue;
                if (kn.CidrIpRanges != null)
                {
                    foreach (var cidr in kn.CidrIpRanges)
                    {
                        data.NetworkPolicies.Add(new HealthCheckCloudDataNetworkPolicy()
                        {
                            Name = kn.NetworkName,
                            Definition = cidr,
                            Type = "CIDR",
                            Trusted = kn.Categories.Contains("trusted"),
                            ApplyToUnknownCountry = kn.ApplyToUnknownCountry,
                        });
                    }

                }
                if (kn.CountryIsoCodes != null)
                {
                    foreach (var country in kn.CountryIsoCodes)
                    {
                        data.NetworkPolicies.Add(new HealthCheckCloudDataNetworkPolicy()
                        {
                            Name = kn.NetworkName,
                            Definition = country,
                            Type = "Country",
                            Trusted = kn.Categories.Contains("trusted"),
                            ApplyToUnknownCountry = kn.ApplyToUnknownCountry,
                        });
                    }

                }
            }
        }

        private void ExtractPasswordManagementPolicy(GraphAPI.PolicyResponse policy)
        {
            foreach (var detail in policy.policyDetail)
            {
                var policyDetail = GraphAPI.PolicyDetail.LoadFromString(detail);
                var pm = policyDetail.PasswordManagementPolicy;
                if (pm == null)
                    continue;
                foreach (var p in pm)
                {
                    //p.SelfServePasswordResetPolicy.
                }
            }
        }

        private void ExtractCrossTenantPolicy(GraphAPI.PolicyResponse policy)
        {
            foreach (var detail in policy.policyDetail)
            {
                var policyDetail = GraphAPI.PolicyDetail.LoadFromString(detail);
                var cta = policyDetail.CrossTenantAccessPolicy;
                if (cta == null)
                    continue;

                var lastModified = cta.LastModified;

                foreach (var tg in cta.TenantGroup)
                {
                    bool? allowB2BFrom = null;
                    bool? allowNativeFederationFrom = null;
                    bool? allowB2BTo = null;
                    bool? allowNativeFederationTo = null;
                    if (tg.FromMyTenancy != null)
                    {
                        foreach (var t in tg.FromMyTenancy)
                        {
                            if (t.AllowB2B != null)
                                allowB2BFrom = t.AllowB2B.Value;
                            if (t.AllowNativeFederation != null)
                                allowNativeFederationFrom = t.AllowNativeFederation.Value;
                        }
                    }
                    if (tg.ToMyTenancy != null)
                    {
                        foreach (var t in tg.ToMyTenancy)
                        {
                            if (t.AllowB2B != null)
                                allowB2BTo = t.AllowB2B.Value;
                            if (t.AllowNativeFederation != null)
                                allowNativeFederationTo = t.AllowNativeFederation.Value;
                        }
                    }
                    foreach (var t in tg.Tenants)
                    {
                        var ctp = new HealthCheckCloudDataCrossTenantPolicy()
                        {
                            TenantId = t,
                            lastModified = lastModified,
                            AllowB2BFrom = allowB2BFrom,
                            AllowB2BTo = allowB2BTo,
                            AllowNativeFederationFrom = allowNativeFederationFrom,
                            AllowNativeFederationTo = allowNativeFederationTo,
                        };
                        data.CrossTenantPolicies.Add(ctp);
                    }
                }
            }
        }

        private void AnalyzeAllUsers(IReadOnlyDictionary<string, HealthCheckCloudDataRoleMember> adminCache)
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

            Dictionary<string, int> MFAMethod = new Dictionary<string, int>();
            Dictionary<string, int> MFAMethodDefault = new Dictionary<string, int>();
            data.NumberOfUsers = 0;

            var properties = new string[] {
                "userPrincipalName",
                "userType",
                "immutableId",
                "userState",
                "userStateChangedOn",
            };

            var graph = new GraphAPI(credential);
            graph.GetUsers(properties, (GraphAPI.User user) =>
            {
                data.NumberOfUsers++;

                if ((data.NumberOfUsers % 500) == 0)
                {
                    Console.Write("+");
                    Trace.Write("+");
                }

                if (user.objectId != null)
                {
                    if (adminCache.TryGetValue(user.objectId, out var member))
                    {
                        member.WhenCreated = user.createdDateTime;
                        member.HasImmutableId = user.immutableId != null;
                    }
                    if (appPermissionsToComplete.TryGetValue(user.objectId, out var permissions))
                    {
                        foreach (var permission in permissions)
                        {
                            permission.principalDisplayName = user.userPrincipalName;
                        }
                    }
                }

                int index = user.userPrincipalName.IndexOf("#EXT#@");
                if (user.userType == "Guest" && index > 0)
                {
                    data.NumberofGuests++;
                    int index2 = user.userPrincipalName.LastIndexOf("_", index);
                    if (index2 > 0)
                    {
                        string domain = user.userPrincipalName.Substring(index2 + 1, index - index2 - 1).ToLowerInvariant();
                        if (!ForeignDomainsGuest.ContainsKey(domain))
                            ForeignDomainsGuest[domain] = 0;
                        ForeignDomainsGuest[domain]++;
                    }
                    if (user.userState == "PendingAcceptance")
                    {
                        if (user.userStateChangedOn != null && user.userStateChangedOn.Value.AddMonths(1) < now)
                        {
                            data.OldInvitations.Add(new HealthCheckCloudDataUser()
                            {
                                ObjectId = user.objectId,
                                UserPrincipalName = user.userPrincipalName,
                                WhenCreated = user.createdDateTime,
                                //LastPasswordChangeTimestamp = user.LastPasswordChangeTimestamp,
                                //PasswordNeverExpires = user.PasswordNeverExpires,
                                HasImmutableId = user.immutableId != null,
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
                        int index2 = user.userPrincipalName.LastIndexOf("_", index);
                        if (index2 > 0)
                        {
                            string domain = user.userPrincipalName.Substring(index2 + 1, index - index2 - 1).ToLowerInvariant();
                            if (!ForeignDomainsMember.ContainsKey(domain))
                                ForeignDomainsMember[domain] = 0;
                            ForeignDomainsMember[domain]++;
                        }
                    }
                    else
                    {
                        data.NumberofInternalMembers++;
                        if (!string.IsNullOrEmpty(user.immutableId))
                        {
                            data.NumberofSyncInternalMembers++;
                        }
                        else
                        {
                            data.NumberofPureAureInternalMembers++;
                        }

                        /*if (user.LastPasswordChangeTimestamp != null && user.LastPasswordChangeTimestamp.Value.AddDays(90) < now)
                        {
                            data.UsersInactive.Add(new HealthCheckCloudDataUser()
                            {
                                ObjectId = user.objectId,
                                UserPrincipalName = user.userPrincipalName,
                                WhenCreated = user.createdDateTime,
                                LastPasswordChangeTimestamp = user.LastPasswordChangeTimestamp,
                                PasswordNeverExpires = user.PasswordNeverExpires,
                                HasImmutableId = user.immutableId != null,
                            });
                        }
                        if (user.PasswordNeverExpires != null && user.PasswordNeverExpires.Value)
                        {
                            data.UsersPasswordNeverExpires.Add(new HealthCheckCloudDataUser()
                            {
                                ObjectId = user.objectId,
                                UserPrincipalName = user.userPrincipalName,
                                WhenCreated = user.createdDateTime,
                                LastPasswordChangeTimestamp = user.LastPasswordChangeTimestamp,
                                PasswordNeverExpires = user.PasswordNeverExpires,
                                HasImmutableId = user.immutableId != null,
                            });
                        }*/
                    }
                }
            });

            /*
            var provisioningApi = new ProvisioningApi(credential);
            
            var properties = new string[] {
                "UserPrincipalName",
                "LastPasswordChangeTimestamp",
                "UserType",
                "PasswordNeverExpires",
                "StrongAuthenticationMethods",
                "ImmutableId",
            };

            ProvisioningApi.ListUserResults r = null;
            do
            {
                if (r == null)
                {
                    var k = provisioningApi.ListUsers(properties);
                    r = k.ReturnValue;
                }
                else
                {
                    Console.Write("+");
                    Trace.Write("+");
                    var k = provisioningApi.NavigateUserResults(r.ListContext);
                    r = k.ReturnValue;
                }
                foreach (var user in r.Results)
                {
                    data.NumberOfUsers++;

                    if (user.ObjectId != null && adminCache.ContainsKey((Guid)user.ObjectId))
                    {
                        var m = adminCache[(Guid)user.ObjectId];
                        m.WhenCreated = user.WhenCreated;
                        m.LastPasswordChangeTimestamp = user.LastPasswordChangeTimestamp;
                        m.PasswordNeverExpires = user.PasswordNeverExpires;
                        m.HasImmutableId = user.ImmutableId != null;
                    }
                    if (user.ObjectId != null && appPermissionsToComplete.ContainsKey((Guid)user.ObjectId))
                    {
                        foreach (var permission in appPermissionsToComplete[(Guid)user.ObjectId])
                        {
                            permission.principalDisplayName = user.UserPrincipalName;
                        }
                    }

                    int index = user.UserPrincipalName.IndexOf("#EXT#@");
                    if (user.UserType.HasValue && user.UserType.Value == ProvisioningApi.UserType.Guest && index > 0)
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
                            if (!string.IsNullOrEmpty(user.ImmutableId))
                            {
                                data.NumberofSyncInternalMembers++;
                            }
                            else
                            {
                                data.NumberofPureAureInternalMembers++;
                            }

                            if (user.LastPasswordChangeTimestamp != null && user.LastPasswordChangeTimestamp.Value.AddDays(90) < now)
                            {
                                data.UsersInactive.Add(new HealthCheckCloudDataUser()
                                {
                                    ObjectId = user.ObjectId,
                                    UserPrincipalName = user.UserPrincipalName,
                                    WhenCreated = user.WhenCreated,
                                    LastPasswordChangeTimestamp = user.LastPasswordChangeTimestamp,
                                    PasswordNeverExpires = user.PasswordNeverExpires,
                                    HasImmutableId = user.ImmutableId != null,
                                });
                            }
                            if (user.PasswordNeverExpires != null && user.PasswordNeverExpires.Value)
                            {
                                data.UsersPasswordNeverExpires.Add(new HealthCheckCloudDataUser()
                                {
                                    ObjectId = user.ObjectId,
                                    UserPrincipalName = user.UserPrincipalName,
                                    WhenCreated = user.WhenCreated,
                                    LastPasswordChangeTimestamp = user.LastPasswordChangeTimestamp,
                                    PasswordNeverExpires = user.PasswordNeverExpires,
                                    HasImmutableId = user.ImmutableId != null,
                                });
                            }
                        }
                    }
                }
            } while (!r.IsLastPage);
            */
            Console.WriteLine();

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
                        OverallProvisioningStatus = await CalculateOverallProvisioningStatus(api, member.Id),
                        ValidationStatus = member.State,
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
            Console.WriteLine(value);
            Trace.WriteLine(value);
        }

        private void DisplayAdvancementWarning(string data)
        {
            string value = "[" + DateTime.Now.ToLongTimeString() + "] " + data;
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine(value);
            Console.ResetColor();
            Trace.WriteLine(value);
        }
    }
}
