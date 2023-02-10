//
// Copyright (c) Vincent LE TOUX for Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using Newtonsoft.Json;
using PingCastle.Cloud.Common;
using PingCastle.Cloud.Credentials;
using PingCastle.Cloud.Tokens;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace PingCastle.Cloud.RESTServices.Azure
{
    [AzureService("1b730954-1685-4b74-9bfd-dac224a7b894", "https://graph.windows.net")]
    public class GraphAPI : RESTClientBase<GraphAPI>, IAzureService
    {
        public GraphAPI(IAzureCredential credential) : base(credential)
        {
        }

        //https://docs.microsoft.com/fr-fr/previous-versions/azure/ad/graph/api/policy-operations
        protected override string BuidEndPoint(string function, string optionalQuery)
        {
            var query = HttpUtility.ParseQueryString(optionalQuery);
            query["api-version"] = "1.61-internal";

            var builder = new UriBuilder("https://graph.windows.net/" + credential.Tenantid + "/" + function);
            builder.Query = query.ToString();
            return builder.ToString();
        }

        public PolicyResponseRoot GetPolicies()
        {
            return CallEndPoint<PolicyResponseRoot>("policies");
        }

        public User GetUser(string objectId)
        {
            return CallEndPoint<User>("users/" + objectId);
        }

        public void GetUsers(Action<User> action)
        {
            GetUsers(null, action);
        }

        public void GetUsers(string[] properties, Action<User> action)
        {
            var query = HttpUtility.ParseQueryString("");
            if( properties != null && properties.Length > 0)
                query["$select"] = string.Join(",", properties);
            CallEndPointWithPaggingAndActionAsync<object, User>("users", null, action, query.ToString()).GetAwaiter().GetResult();
        }

        public List<Membership> GetUserMembership(string objectId)
        {
            return CallEndPointWithPagging<Membership>("users/" + objectId + "/memberOf");
        }

        public void GetGroupMembers(string objectId, Action<User>action)
        {
            CallEndPointWithPaggingAndActionAsync<object, User>("groups/" + objectId + "/members", null, action).GetAwaiter().GetResult();
        }

        public List<ServicePrincipal> GetServicePrincipals()
        {
            return CallEndPointWithPagging<ServicePrincipal>("servicePrincipals");
        }
        // Get-AzureADOAuth2PermissionGrant
        public List<OAuth2PermissionGrant> GetOAuth2PermissionGrants()
        {
            return CallEndPointWithPagging<OAuth2PermissionGrant>("oauth2PermissionGrants");
        }

        public AzureADObject GetObjectsByObjectIds(string id)
        {
            var o = CallEndPointWithPagging<AzureADObjectRequest, AzureADObject>("getObjectsByObjectIds", 
                new AzureADObjectRequest { objectIds = new List<string> { id } });
            return o.First();
        }

        // Get-AzureADServiceAppRoleAssignedTo
        public List<appRoleAssignedTo> GetAppRoleAssignedTo(string applicationId)
        {

            var r = CallEndPointWithPagging<appRoleAssignedTo>("servicePrincipals/" + applicationId + "/appRoleAssignedTo");

            return r;
        }
        // Get-AzureADOAuth2PermissionGrant

        // Get-AzureADServicePrincipalMembership
        public List<memberOf> GetMemberOf(string applicationId)
        {

            var r = CallEndPointWithPagging<memberOf>("servicePrincipals/" + applicationId + "/memberOf");

            return r;
        }

        public class AzureADObject
        {
            public List<AppRole> appRoles { get; set; }
        }
        public class AzureADObjectRequest
        {
            public List<string> objectIds { get; set; }
        }
        public class IncludeCondition
        {
            public string ClientType { get; set; }
            public List<string> Groups { get; set; }
            public List<string> DevicePlatforms { get; set; }
        }

        public class ExcludeCondition
        {
            public List<string> Groups { get; set; }
            public List<string> AppIds { get; set; }
        }

        public class DeviceStatePolicy
        {
            public string Mode { get; set; }
            public List<string> RequiredDeviceState { get; set; }
            public List<IncludeCondition> IncludeConditions { get; set; }
            public List<ExcludeCondition> ExcludeConditions { get; set; }
        }

        public class AuthenticationPolicies
        {
            public string Version { get; set; }
            public bool PoliciesEnabled { get; set; }
            public List<DeviceStatePolicy> DeviceStatePolicies { get; set; }
            public List<object> ManagedApps { get; set; }
        }

        public class FromToMyTenancy
        {
            public bool? AllowB2B { get; set; }
            public bool? AllowNativeFederation { get; set; }
        }

        public class TenantGroup
        {
            public List<string> Tenants { get; set; }
            public List<FromToMyTenancy> ToMyTenancy { get; set; }
            public List<FromToMyTenancy> FromMyTenancy { get; set; }
        }

        public class CrossTenantAccessPolicy
        {
            public int Version { get; set; }
            public int MigrationStatus { get; set; }
            public string LastModified { get; set; }
            public List<TenantGroup> TenantGroup { get; set; }
        }

        public class InvitationsAllowedAndBlockedDomainsPolicy
        {
            public List<object> BlockedDomains { get; set; }
        }

        public class PreviewPolicy
        {
            public List<string> Features { get; set; }
        }

        public class AutoRedeemPolicy
        {
            public List<object> AdminConsentedForUsersIntoTenantIds { get; set; }
            public List<object> NoAADConsentForUsersFromTenantsIds { get; set; }
        }

        public class B2BManagementPolicy
        {
            public InvitationsAllowedAndBlockedDomainsPolicy InvitationsAllowedAndBlockedDomainsPolicy { get; set; }
            public PreviewPolicy PreviewPolicy { get; set; }
            public AutoRedeemPolicy AutoRedeemPolicy { get; set; }
        }

        public class SecurityQuestionsLink
        {
            public int Type { get; set; }
        }

        public class SelfServePasswordResetPolicy
        {
            public int EnablementForUsers { get; set; }
            public List<int> SelectedContactMethodsForUsers { get; set; }
            public int NumberOfRequiredContactMethodsForUsers { get; set; }
            public int NumberOfSecurityQuestionsToRegister { get; set; }
            public int NumberOfSecurityQuestionsToVerify { get; set; }
            public int EnforcedRegistrationEnablementForUsers { get; set; }
            public int EnforcedRegistrationIntervalInDaysForUsers { get; set; }
            public bool EnforcedRegistrationAllowSkip { get; set; }
            public bool CustomizeContactAdminLink { get; set; }
            public string CustomContactAdminLink { get; set; }
            public bool NotifyUsersOfReset { get; set; }
            public bool NotifyTenantAdminOfReset { get; set; }
            public bool RestrictSelfServePasswordResetAccess { get; set; }
            public bool EnableEnforcedRegistrationOnSignin { get; set; }
            public int PolicySource { get; set; }
            public object EnableAccountUnlock { get; set; }
            public bool IsJustInTimeMigration { get; set; }
            public int DefaultPolicyStatus { get; set; }

            [JsonProperty("DefaultPolicyOptoutId ")]
            public object DefaultPolicyOptoutId { get; set; }
            public object DefaultPolicyStatusLastUpdatedDateTime { get; set; }
            public List<object> ConditionalAccessPolicies { get; set; }
            public SecurityQuestionsLink SecurityQuestionsLink { get; set; }
            public List<IncludeCondition> IncludeConditions { get; set; }
            public int Version { get; set; }
            public DateTime LastModified { get; set; }
        }

        public class PasswordManagementPolicy
        {
            public string Id { get; set; }
            public DateTime LastModified { get; set; }
            public int Version { get; set; }
            public SelfServePasswordResetPolicy SelfServePasswordResetPolicy { get; set; }
        }

        public class KnownNetworkPolicies
        {
            public string NetworkName { get; set; }
            public string NetworkId { get; set; }
            public List<string> CidrIpRanges { get; set; }
            public List<string> CountryIsoCodes { get; set; }
            public List<string> Categories { get; set; }
            public bool ApplyToUnknownCountry { get; set; }
        }

        public class PolicyDetail : JsonSerialization<PolicyDetail>
        {
            public KnownNetworkPolicies KnownNetworkPolicies { get; set; }
            public CrossTenantAccessPolicy CrossTenantAccessPolicy { get; set; }
            public AuthenticationPolicies AuthenticationPolicies { get; set; }
            public B2BManagementPolicy B2BManagementPolicy { get; set; }
            public List<PasswordManagementPolicy> PasswordManagementPolicy { get; set; }
        }

        public class PolicyResponse
        {
            [JsonProperty("odata.type")]
            public string OdataType { get; set; }
            public string objectType { get; set; }
            public string objectId { get; set; }
            public object deletionTimestamp { get; set; }
            public string displayName { get; set; }
            public List<object> keyCredentials { get; set; }
            public int policyType { get; set; }
            public List<string> policyDetail { get; set; }
            public object policyIdentifier { get; set; }
            public int? tenantDefaultPolicy { get; set; }
        }

        public class PolicyResponseRoot
        {
            [JsonProperty("odata.metadata")]
            public string OdataMetadata { get; set; }
            public List<PolicyResponse> value { get; set; }
        }

        // Root myDeserializedClass = JsonConvert.DeserializeObject<Root>(myJsonResponse);
        public class AddIn
        {
            public string id { get; set; }
            public string type { get; set; }
            public List<Property> properties { get; set; }
        }

        public class AppRole
        {
            public List<string> allowedMemberTypes { get; set; }
            public string description { get; set; }
            public string displayName { get; set; }
            public string id { get; set; }
            public bool isEnabled { get; set; }
            public string value { get; set; }
        }

        public class InformationalUrls
        {
            public string termsOfService { get; set; }
            public object support { get; set; }
            public string privacy { get; set; }
            public object marketing { get; set; }
        }

        public class KeyCredential
        {
            public string customKeyIdentifier { get; set; }
            public DateTime endDate { get; set; }
            public string keyId { get; set; }
            public DateTime startDate { get; set; }
            public string type { get; set; }
            public string usage { get; set; }
            public object value { get; set; }
        }

        public class Oauth2Permission
        {
            public string adminConsentDescription { get; set; }
            public string adminConsentDisplayName { get; set; }
            public string id { get; set; }
            public bool isEnabled { get; set; }
            public string type { get; set; }
            public string userConsentDescription { get; set; }
            public string userConsentDisplayName { get; set; }
            public string value { get; set; }
        }

        public class PasswordCredential
        {
            public string customKeyIdentifier { get; set; }
            public DateTime endDate { get; set; }
            public string keyId { get; set; }
            public DateTime startDate { get; set; }
            public object value { get; set; }
        }

        public class Property
        {
            public string key { get; set; }
            public string value { get; set; }
        }

        // Root myDeserializedClass = JsonConvert.DeserializeObject<Root>(myJsonResponse);
        public class User
        {
            [JsonProperty("odata.metadata")]
            public string OdataMetadata { get; set; }

            [JsonProperty("odata.type")]
            public string OdataType { get; set; }
            public string objectType { get; set; }
            public string objectId { get; set; }
            public object deletionTimestamp { get; set; }
            public object accountEnabled { get; set; }
            public object ageGroup { get; set; }
            public List<object> assignedLicenses { get; set; }
            public List<object> assignedPlans { get; set; }
            public object city { get; set; }
            public object companyName { get; set; }
            public object consentProvidedForMinor { get; set; }
            public object country { get; set; }
            public DateTime? createdDateTime { get; set; }
            public object creationType { get; set; }
            public object department { get; set; }
            public object dirSyncEnabled { get; set; }
            public string displayName { get; set; }
            public object employeeId { get; set; }
            public object facsimileTelephoneNumber { get; set; }
            public object givenName { get; set; }
            public string immutableId { get; set; }
            public object isCompromised { get; set; }
            public object jobTitle { get; set; }
            public object lastDirSyncTime { get; set; }
            public object legalAgeGroupClassification { get; set; }
            public string mail { get; set; }
            public object mailNickname { get; set; }
            public object mobile { get; set; }
            public object onPremisesDistinguishedName { get; set; }
            public object onPremisesSecurityIdentifier { get; set; }
            public List<string> otherMails { get; set; }
            public object passwordPolicies { get; set; }
            public object passwordProfile { get; set; }
            public object physicalDeliveryOfficeName { get; set; }
            public object postalCode { get; set; }
            public object preferredLanguage { get; set; }
            public List<object> provisionedPlans { get; set; }
            public List<object> provisioningErrors { get; set; }
            public List<object> proxyAddresses { get; set; }
            public object refreshTokensValidFromDateTime { get; set; }
            public object showInAddressList { get; set; }
            public List<object> signInNames { get; set; }
            public object sipProxyAddress { get; set; }
            public object state { get; set; }
            public object streetAddress { get; set; }
            public object surname { get; set; }
            public object telephoneNumber { get; set; }
            public object usageLocation { get; set; }
            public List<object> userIdentities { get; set; }
            public string userPrincipalName { get; set; }
            public string userState { get; set; }
            public DateTime? userStateChangedOn { get; set; }
            public string userType { get; set; }
        }

        public class Membership
        {
            [JsonProperty("odata.type")]
            public string OdataType { get; set; }
            public string objectType { get; set; }
            public string objectId { get; set; }
            public object deletionTimestamp { get; set; }
            public string description { get; set; }
            public string displayName { get; set; }
            public object isSystem { get; set; }
            public object roleDisabled { get; set; }
            public object roleTemplateId { get; set; }
            public object dirSyncEnabled { get; set; }
            public object lastDirSyncTime { get; set; }
            public object mail { get; set; }
            public string mailNickname { get; set; }
            public bool? mailEnabled { get; set; }
            public object onPremisesDomainName { get; set; }
            public object onPremisesNetBiosName { get; set; }
            public object onPremisesSamAccountName { get; set; }
            public object onPremisesSecurityIdentifier { get; set; }
            public List<object> provisioningErrors { get; set; }
            public List<object> proxyAddresses { get; set; }
            public bool? securityEnabled { get; set; }
        }
        

        //https://docs.microsoft.com/en-us/graph/api/resources/serviceprincipal?view=graph-rest-1.0
        public class ServicePrincipal
        {
            [JsonProperty("odata.type")]
            public string OdataType { get; set; }
            public string objectType { get; set; }
            public string objectId { get; set; }
            public DateTime? deletionTimestamp { get; set; }
            public bool accountEnabled { get; set; }
            public List<AddIn> addIns { get; set; }
            public List<string> alternativeNames { get; set; }
            public string appDisplayName { get; set; }
            public string appId { get; set; }
            public string applicationTemplateId { get; set; }
            public string appOwnerTenantId { get; set; }
            public bool appRoleAssignmentRequired { get; set; }
            public List<AppRole> appRoles { get; set; }
            public string displayName { get; set; }
            public string errorUrl { get; set; }
            public string homepage { get; set; }
            public InformationalUrls informationalUrls { get; set; }
            public List<KeyCredential> keyCredentials { get; set; }
            public string logoutUrl { get; set; }
            public List<string> notificationEmailAddresses { get; set; }
            public List<Oauth2Permission> oauth2Permissions { get; set; }
            public List<PasswordCredential> passwordCredentials { get; set; }
            public string preferredSingleSignOnMode { get; set; }
            public DateTime? preferredTokenSigningKeyEndDateTime { get; set; }
            public string preferredTokenSigningKeyThumbprint { get; set; }
            public string publisherName { get; set; }
            public List<string> replyUrls { get; set; }
            //https://docs.microsoft.com/en-us/dotnet/api/microsoft.azure.management.graph.rbac.fluent.models.applicationinner.samlmetadataurl?view=azure-dotnet
            public string samlMetadataUrl { get; set; }
            public object samlSingleSignOnSettings { get; set; }
            public List<string> servicePrincipalNames { get; set; }
            public string servicePrincipalType { get; set; }
            public string signInAudience { get; set; }
            public List<string> tags { get; set; }
            public string tokenEncryptionKeyId { get; set; }
        }

        public class appRoleAssignedTo
        {
            [JsonProperty("odata.type")]
            public string OdataType { get; set; }
            public string objectType { get; set; }
            public string objectId { get; set; }
            public DateTime? deletionTimestamp { get; set; }
            public DateTime creationTimestamp { get; set; }
            public string id { get; set; }
            public string principalDisplayName { get; set; }
            public string principalId { get; set; }
            public string principalType { get; set; }
            public string resourceDisplayName { get; set; }
            public string resourceId { get; set; }
        }


        public class memberOf
        {
            [JsonProperty("odata.type")]
            public string OdataType { get; set; }
            public string objectType { get; set; }
            public string objectId { get; set; }
            public DateTime? deletionTimestamp { get; set; }
            public string description { get; set; }
            public string displayName { get; set; }
            public bool isSystem { get; set; }
            public bool roleDisabled { get; set; }
            public string roleTemplateId { get; set; }
        }


        public class OAuth2PermissionGrant
        {
            public string clientId { get; set; }
            public string consentType { get; set; }
            public DateTime expiryTime { get; set; }
            public string objectId { get; set; }
            public string principalId { get; set; }
            public string resourceId { get; set; }
            public string scope { get; set; }
            public DateTime startTime { get; set; }
        }
    }
}
