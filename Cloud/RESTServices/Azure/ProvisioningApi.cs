//
// Copyright (c) Vincent LE TOUX for Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Cloud.Common;
using PingCastle.Cloud.Credentials;
using PingCastle.Cloud.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.Serialization;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Dispatcher;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace PingCastle.Cloud.RESTServices.Azure
{
    [AzureService("1b730954-1685-4b74-9bfd-dac224a7b894", "https://graph.windows.net")]
    public class ProvisioningApi : IAzureService
    {
        public ProvisioningApi(IAzureCredential credential)
        {
            this.credential = credential;
        }

        public IAzureCredential credential { get; private set; }

        public GetCompanyInformationResponse GetCompanyInfo()
        {
            var o = callSOAP((serviceProxy) =>
                serviceProxy.GetCompanyInformation(new Request())
                );
            return o;
        }

        public GetCompanyDirSyncFeaturesResponse GetCompanyDirSyncFeatures()
        {
            var o = callSOAP((serviceProxy) =>
                serviceProxy.GetCompanyDirSyncFeatures(new GetCompanyDirSyncFeaturesRequest())
                );
            return o;
        }

        public ListDomainsResponse ListDomains()
        {
            var o = callSOAP((serviceProxy) =>
                serviceProxy.ListDomains(new ListDomainsRequest())
                );
            return o;
        }

        public ListRolesResponse ListRoles()
        {
            var o = callSOAP((serviceProxy) =>
                serviceProxy.ListRoles(new Request())
                );
            return o;
        }

        public ListRoleMembersResponse ListRoleMembers(Guid roleGuid, IEnumerable<string> properties = null)
        {
            var o = callSOAP((serviceProxy) =>
                serviceProxy.ListRoleMembers(new ListRoleMembersRequest()
                {
                    RoleMemberSearchDefinition = new RoleMemberSearchDefinition()
                    {
                        PageSize = 500, // to do: more than 500
                        RoleObjectId = roleGuid,
                        IncludedProperties = properties == null ? null : new List<string>(properties),
                    }
                })
                );
            return o;
        }

        public ListUsersResponse ListUsers(IEnumerable<string> properties = null)
        {
            var o = callSOAP((serviceProxy) =>
                serviceProxy.ListUsers(new ListUsersRequest()
                {
                    UserSearchDefinition = new UserSearchDefinition()
                        {
                            PageSize = 500,
                            IncludedProperties = properties == null ? null :new List<string>(properties),
                        }
                })
                );
            return o;
        }

        public ListUsersByStrongAuthenticationResponse ListUsersByStrongAuthentication(string Kind, Guid roleId, IEnumerable<string> properties = null)
        {
            var UserSearchDefinition = new UserSearchByStrongAuthenticationDefinition()
            {
                PageSize = 500,
                IncludedProperties = properties == null ? null : new List<string>(properties),
                RoleObjectId = roleId,
            };
            switch(Kind)
            {
                case "Disabled":
                    UserSearchDefinition.RequirementUnsetOnly = true;
                    break;
                case "Enforced":
                case "Enabled":
                    UserSearchDefinition.Requirements = new List<StrongAuthenticationRequirement>();
                    UserSearchDefinition.Requirements.Add(new StrongAuthenticationRequirement()
                    {
                        RelyingParty = "*",
                        State = Kind,
                    });
                    break;
                default:
                    throw new NotImplementedException("Unknown kind " + Kind);
            }
            var o = callSOAP((serviceProxy) =>
                serviceProxy.ListUsersByStrongAuthentication(new ListUsersByStrongAuthenticationRequest()
                {
                    UserSearchDefinition = UserSearchDefinition,
                })
                );
            return o;
        }

        public NavigateUserResultsResponse NavigateUserResults(byte[] context)
        {
            var o = callSOAP((serviceProxy) =>
                serviceProxy.NavigateUserResults(new NavigateUserResultsRequest()
                {
                    PageToNavigate = Page.Next,
                    ListContext = context,
                })
                );
            return o;
        }

        [DataContract(Name = "Response", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService")]
        [KnownType(typeof(GetCompanyInformationResponse))]
        public class Response : IExtensibleDataObject
        {
            private ExtensionDataObject extensionDataField;

            public ExtensionDataObject ExtensionData
            {
                get
                {
                    return extensionDataField;
                }
                set
                {
                    extensionDataField = value;
                }
            }
        }
        #region company info
        [DataContract(Name = "AuthorizedService", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public enum AuthorizedService
        {
            [EnumMember]
            Blackberry,
            [EnumMember]
            Other
        }

        [DataContract(Name = "CompanyType", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public enum CompanyType
        {
            [EnumMember]
            CompanyTenant,
            [EnumMember]
            MicrosoftSupportTenant,
            [EnumMember]
            SyndicatePartnerTenant,
            [EnumMember]
            SupportPartnerTenant,
            [EnumMember]
            ResellerPartnerTenant,
            [EnumMember]
            ValueAddedResellerPartnerTenant
        }

        [DataContract(Name = "DirSyncStatus", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public enum DirSyncStatus
        {
            [EnumMember]
            Disabled,
            [EnumMember]
            Enabled,
            [EnumMember]
            PendingEnabled,
            [EnumMember]
            PendingDisabled,
            [EnumMember]
            Other
        }

        [DataContract(Name = "O365TenantReleaseTrack", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public enum O365TenantReleaseTrack
        {
            [EnumMember]
            Other,
            [EnumMember]
            FirstRelease,
            [EnumMember]
            StagedRollout,
            [EnumMember]
            Dogfood
        }
        [CollectionDataContract(Name = "ArrayOfXElement", Namespace = "http://schemas.datacontract.org/2004/07/System.Xml.Linq", ItemName = "XElement")]
        public class ArrayOfXElement : List<XmlElement>
        {
        }
        [DataContract(Name = "ServiceInformation", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public class ServiceInformation : IExtensibleDataObject
        {
            public ExtensionDataObject ExtensionData { get; set; }


            [DataMember]
            public ArrayOfXElement ServiceElements { get; set; }


            [DataMember]
            public string ServiceInstance { get; set; }
        }
        [DataContract(Name = "GeographicLocation", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public class GeographicLocation : IExtensibleDataObject
        {

            public ExtensionDataObject ExtensionData { get; set; }

            [DataMember]
            public string Country { get; set; }

            [DataMember]
            public string Region { get; set; }

            [DataMember]
            public string State { get; set; }
        }

        [DataContract(Name = "ServiceEndpoint", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public class ServiceEndpoint : IExtensibleDataObject
        {

            public ExtensionDataObject ExtensionData { get; set; }

            [DataMember]
            public string Address { get; set; }

            [DataMember]
            public string Name { get; set; }
        }

        [DataContract(Name = "ServiceInstanceInformation", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public class ServiceInstanceInformation : IExtensibleDataObject
        {

            public ExtensionDataObject ExtensionData { get; set; }

            [DataMember]
            public GeographicLocation GeographicLocation { get; set; }

            [DataMember]
            public string ServiceInstance { get; set; }

            [DataMember]
            public List<ServiceEndpoint> ServiceInstanceEndpoints { get; set; }
        }

        [DataContract(Name = "CompanyInformation", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public class CompanyInformation : IExtensibleDataObject
        {
            public ExtensionDataObject ExtensionData { get; set; }

            [DataMember]
            public bool? AllowAdHocSubscriptions { get; set; }

            [DataMember]
            public bool? AllowEmailVerifiedUsers { get; set; }

            [DataMember]
            public List<string> AuthorizedServiceInstances { get; set; }

            [DataMember]
            public List<AuthorizedService> AuthorizedServices { get; set; }

            [DataMember]
            public string City { get; set; }

            [DataMember]
            public DateTime? CompanyDeletionStartTime { get; set; }

            [DataMember]
            public List<string> CompanyTags { get; set; }

            [DataMember]
            public CompanyType CompanyType { get; set; }

            [DataMember]
            public bool? CompassEnabled { get; set; }

            [DataMember]
            public string Country { get; set; }

            [DataMember]
            public string CountryLetterCode { get; set; }

            [DataMember]
            public bool? DapEnabled { get; set; }

            [DataMember]
            public string DefaultUsageLocation { get; set; }

            [DataMember]
            public string DirSyncApplicationType { get; set; }

            [DataMember]
            public string DirSyncClientMachineName { get; set; }

            [DataMember]
            public string DirSyncClientVersion { get; set; }

            [DataMember]
            public string DirSyncServiceAccount { get; set; }

            [DataMember]
            public bool? DirectorySynchronizationEnabled { get; set; }

            [DataMember]
            public DirSyncStatus DirectorySynchronizationStatus { get; set; }

            [DataMember]
            public string DisplayName { get; set; }

            [DataMember]
            public string InitialDomain { get; set; }

            [DataMember]
            public DateTime? LastDirSyncTime { get; set; }

            [DataMember]
            public DateTime? LastPasswordSyncTime { get; set; }

            [DataMember]
            public List<string> MarketingNotificationEmails { get; set; }

            [DataMember]
            public bool? MultipleDataLocationsForServicesEnabled { get; set; }

            [DataMember]
            public Guid? ObjectId { get; set; }

            [DataMember]
            public bool? PasswordSynchronizationEnabled { get; set; }

            [DataMember]
            public XmlElement PortalSettings { get; set; }

            [DataMember]
            public string PostalCode { get; set; }

            [DataMember]
            public string PreferredLanguage { get; set; }

            [DataMember]
            public O365TenantReleaseTrack? ReleaseTrack { get; set; }

            [DataMember]
            public string ReplicationScope { get; set; }

            [DataMember]
            public bool? RmsViralSignUpEnabled { get; set; }

            [DataMember]
            public List<string> SecurityComplianceNotificationEmails { get; set; }

            [DataMember]
            public List<string> SecurityComplianceNotificationPhones { get; set; }

            [DataMember]
            public bool SelfServePasswordResetEnabled { get; set; }

            [DataMember]
            public List<ServiceInformation> ServiceInformation { get; set; }

            [DataMember]
            public List<ServiceInstanceInformation> ServiceInstanceInformation { get; set; }

            [DataMember]
            public string State { get; set; }

            [DataMember]
            public string Street { get; set; }

            [DataMember]
            public bool? SubscriptionProvisioningLimited { get; set; }

            [DataMember]
            public List<string> TechnicalNotificationEmails { get; set; }

            [DataMember]
            public string TelephoneNumber { get; set; }

            [DataMember]
            public Dictionary<string, string> UIExtensibilityUris { get; set; }

            [DataMember]
            public bool UsersPermissionToCreateGroupsEnabled { get; set; }

            [DataMember]
            public bool UsersPermissionToCreateLOBAppsEnabled { get; set; }

            [DataMember]
            public bool UsersPermissionToReadOtherUsersEnabled { get; set; }

            [DataMember]
            public bool UsersPermissionToUserConsentToAppEnabled { get; set; }
            [DataMember]
            public DateTime WhenCreated { get; set; }
        }
        #endregion

        #region domain list
        [DataContract(Name = "DomainAuthenticationType", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public enum DomainAuthenticationType
        {
            [EnumMember]
            Managed,
            [EnumMember]
            Federated
        }
        [Flags]
        [DataContract(Name = "DomainCapabilities", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public enum DomainCapabilities
        {
            [EnumMember]
            None = 0x0,
            [EnumMember]
            Email = 0x1,
            [EnumMember]
            Sharepoint = 0x2,
            [EnumMember]
            OfficeCommunicationsOnline = 0x4,
            [EnumMember]
            SharepointDefault = 0x8,
            [EnumMember]
            FullRedelegation = 0x10,
            [EnumMember]
            SharePointPublic = 0x80,
            [EnumMember]
            OrgIdAuthentication = 0x100,
            [EnumMember]
            Yammer = 0x200,
            [EnumMember]
            Intune = 0x400,
            [EnumMember]
            All = 0x79F
        }
        [DataContract(Name = "DomainStatus", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public enum DomainStatus
        {
            [EnumMember]
            Unverified,
            [EnumMember]
            Verified,
            [EnumMember]
            PendingDeletion
        }

        public class DomainSearchFilter : IExtensibleDataObject
        {
            public ExtensionDataObject ExtensionData { get; set; }
            [DataMember]
            public DomainAuthenticationType? Authentication { get; set; }

            [DataMember]
            public DomainCapabilities? Capability { get; set; }

            [DataMember]
            public DomainStatus? Status { get; set; }
        }
        [DataContract(Name = "DomainVerificationMethod", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public enum DomainVerificationMethod
        {
            [EnumMember]
            None,
            [EnumMember]
            DnsRecord,
            [EnumMember]
            Email
        }
        [DataContract(Name = "Domain", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public class Domain : IExtensibleDataObject
        {

            public ExtensionDataObject ExtensionData { get; set; }

            [DataMember]
            public DomainAuthenticationType? Authentication { get; set; }

            [DataMember]
            public DomainCapabilities? Capabilities { get; set; }

            [DataMember]
            public bool? IsDefault { get; set; }

            [DataMember]
            public bool? IsInitial { get; set; }

            [DataMember]
            public string Name { get; set; }

            [DataMember]
            public string RootDomain { get; set; }

            [DataMember]
            public DomainStatus? Status { get; set; }

            [DataMember]
            public DomainVerificationMethod? VerificationMethod { get; set; }
        }
        [DataContract(Name = "ListDomainsResponse", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService")]
        public class ListDomainsResponse : Response
        {
            [DataMember]
            public List<Domain> ReturnValue { get; set; }
        }

        #endregion

        #region ListRoles
        [DataContract(Name = "Role", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public class Role : IExtensibleDataObject
        {

            public ExtensionDataObject ExtensionData { get; set; }

            [DataMember]
            public string Description { get; set; }

            [DataMember]
            public bool? IsEnabled { get; set; }

            [DataMember]
            public bool? IsSystem { get; set; }

            [DataMember]
            public string Name { get; set; }

            [DataMember]
            public Guid? ObjectId { get; set; }
        }


        [DataContract(Name = "ListRolesResponse", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService")]
        public class ListRolesResponse : Response
        {
            [DataMember]
            public List<Role> ReturnValue { get; set; }
        }
        #endregion

        #region ListRoleMembers
        [DataContract(Name = "SortDirection", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public enum SortDirection
        {
            [EnumMember]
            Ascending,
            [EnumMember]
            Descending
        }

        [DataContract(Name = "SortField", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public enum SortField
        {
            [EnumMember]
            DisplayName,
            [EnumMember]
            UserPrincipalName,
            [EnumMember]
            None
        }

        [DataContract(Name = "SearchDefinition", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        /*[KnownType(typeof(UserSearchByStrongAuthenticationDefinition))]
        [KnownType(typeof(ServicePrincipalSearchDefinition))]
        [KnownType(typeof(AdministrativeUnitSearchDefinition))]
        [KnownType(typeof(AdministrativeUnitMemberSearchDefinition))]
        [KnownType(typeof(PartnerContractSearchDefinition))]
        [KnownType(typeof(DirSyncProvisioningErrorSearchDefinition))]
        [KnownType(typeof(ContactSearchDefinition))]
        [KnownType(typeof(GroupSearchDefinition))]
        [KnownType(typeof(GroupMemberSearchDefinition))]*/
        [KnownType(typeof(RoleMemberSearchDefinition))]
        [KnownType(typeof(RoleScopedMemberSearchDefinition))]
        //[KnownType(typeof(UserSearchDefinition))]
        public class SearchDefinition : IExtensibleDataObject
        {
            public ExtensionDataObject ExtensionData { get; set; }

            [DataMember]
            public int PageSize { get; set; }

            [DataMember]
            public string SearchString { get; set; }

            [DataMember]
            public SortDirection SortDirection { get; set; }

            [DataMember]
            public SortField SortField { get; set; }
        }

        [DataContract(Name = "RoleScopedMemberSearchDefinition", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public class RoleScopedMemberSearchDefinition : RoleMemberSearchDefinition
        {
            [DataMember]
            public Guid? AdministrativeUnitObjectId { get; set; }
        }

        [DataContract(Name = "RoleMemberSearchDefinition", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        [KnownType(typeof(RoleScopedMemberSearchDefinition))]
        public class RoleMemberSearchDefinition : SearchDefinition
        {
            [DataMember]
            public List<string> IncludedProperties { get; set; }

            [DataMember]
            public List<string> MemberObjectTypes { get; set; }

            [DataMember]
            public Guid RoleObjectId { get; set; }
        }

        [DataContract(Name = "ListRoleMembersRequest", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService")]
        public class ListRoleMembersRequest : Request
        {
            [DataMember]
            public RoleMemberSearchDefinition RoleMemberSearchDefinition { get; set; }
        }

        [DataContract(Name = "ProvisioningStatus", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public enum ProvisioningStatus
        {
            [EnumMember]
            None,
            [EnumMember]
            Success,
            [EnumMember]
            Error,
            [EnumMember]
            PendingInput,
            [EnumMember]
            Disabled,
            [EnumMember]
            PendingActivation,
            [EnumMember]
            PendingProvisioning
        }

        [DataContract(Name = "RoleMemberType", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public enum RoleMemberType
        {
            [EnumMember]
            User,
            [EnumMember]
            Group,
            [EnumMember]
            ServicePrincipal,
            [EnumMember]
            Other
        }

        [DataContract(Name = "ValidationStatus", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public enum ValidationStatus
        {
            [EnumMember]
            NotAvailable,
            [EnumMember]
            Healthy,
            [EnumMember]
            Error
        }

        [DataContract(Name = "RoleMember", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public class RoleMember : IExtensibleDataObject
        {
            public ExtensionDataObject ExtensionData { get; set; }

            [DataMember]
            public string DisplayName { get; set; }

            [DataMember]
            public string EmailAddress { get; set; }

            [DataMember]
            public bool? IsLicensed { get; set; }

            [DataMember]
            public DateTime? LastDirSyncTime { get; set; }

            [DataMember]
            public string ObjectId { get; set; }

            [DataMember]
            public ProvisioningStatus? OverallProvisioningStatus { get; set; }

            [DataMember]
            public RoleMemberType RoleMemberType { get; set; }

            [DataMember]
            public List<StrongAuthenticationRequirement> StrongAuthenticationRequirements { get; set; }

            [DataMember]
            public ValidationStatus? ValidationStatus { get; set; }
        }

        [DataContract(Name = "StrongAuthenticationRequirement", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public class StrongAuthenticationRequirement : IExtensibleDataObject
        {
            public ExtensionDataObject ExtensionData { get; set; }

            [DataMember]
            public string RelyingParty { get; set; }

            [DataMember]
            public DateTime RememberDevicesNotIssuedBefore { get; set; }

            [DataMember]
            public string State { get; set; }
        }

        [DataContract(Name = "ListResults", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        /*[KnownType(typeof(ListServicePrincipalResults))]
        [KnownType(typeof(ListAdministrativeUnitResults))]
        [KnownType(typeof(ListAdministrativeUnitMemberResults))]
        [KnownType(typeof(ListPartnerContractResults))]
        [KnownType(typeof(ListObjectsWithDirSyncErrorResults))]
        [KnownType(typeof(ListContactResults))]
        [KnownType(typeof(ListGroupResults))]
        [KnownType(typeof(ListGroupMemberResults))]*/
        [KnownType(typeof(ListRoleMemberResults))]
        /*[KnownType(typeof(ListRoleScopedMemberResults))]
        [KnownType(typeof(ListUserResults))]*/
        public class ListResults : IExtensibleDataObject
        {

            public ExtensionDataObject ExtensionData { get; set; }

            [DataMember]
            public bool IsFirstPage { get; set; }

            [DataMember]
            public bool IsLastPage { get; set; }

            [DataMember]
            public byte[] ListContext { get; set; }
        }

        [DataContract(Name = "ListRoleMemberResults", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public class ListRoleMemberResults : ListResults
        {
            [DataMember]
            public List<RoleMember> Results { get; set; }
        }

        [DataContract(Name = "ListRoleMembersResponse", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService")]
        public class ListRoleMembersResponse : Response
        {
            [DataMember]
            public ListRoleMemberResults ReturnValue { get; set; }
        }
        #endregion

        #region list users
        [DataContract(Name = "AccountSkuIdentifier", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public class AccountSkuIdentifier : IExtensibleDataObject
        {
            public ExtensionDataObject ExtensionData { get; set; }

            [DataMember]
            public string AccountName { get; set; }

            [DataMember]
            public string SkuPartNumber { get; set; }
        }

        [DataContract(Name = "UserEnabledFilter", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public enum UserEnabledFilter
        {
            [EnumMember]
            All,
            [EnumMember]
            EnabledOnly,
            [EnumMember]
            DisabledOnly
        }

        [DataContract(Name = "IndirectLicenseFilter", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public class IndirectLicenseFilter : IExtensibleDataObject
        {
            public ExtensionDataObject ExtensionData { get; set; }

            [DataMember]
            public bool HasErrorsOnly { get; set; }

            [DataMember]
            public Guid ReferenceObjectId { get; set; }
        }

        [DataContract(Name = "UserSearchDefinition", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public class UserSearchDefinition : SearchDefinition
        {
            [DataMember]
            public AccountSkuIdentifier AccountSku { get; set; }

            [DataMember]
            public bool? BlackberryUsersOnly { get; set; }

            [DataMember]
            public string City { get; set; }

            [DataMember]
            public string Country { get; set; }

            [DataMember]
            public string Department { get; set; }

            [DataMember]
            public string DomainName { get; set; }

            [DataMember]
            public UserEnabledFilter? EnabledFilter { get; set; }

            [DataMember]
            public bool? HasErrorsOnly { get; set; }

            [DataMember]
            public List<string> IncludedProperties { get; set; }

            [DataMember]
            public IndirectLicenseFilter IndirectLicenseFilter { get; set; }

            [DataMember]
            public bool? LicenseReconciliationNeededOnly { get; set; }

            [DataMember]
            public bool? ReturnDeletedUsers { get; set; }

            [DataMember]
            public string State { get; set; }

            [DataMember]
            public bool? Synchronized { get; set; }

            [DataMember]
            public string Title { get; set; }

            [DataMember]
            public bool? UnlicensedUsersOnly { get; set; }

            [DataMember]
            public string UsageLocation { get; set; }
        }


        [DataContract(Name = "ListUsersRequest", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService")]
        public class ListUsersRequest : Request
        {
            [DataMember]
            public UserSearchDefinition UserSearchDefinition { get; set; }
        }

        [DataContract(Name = "AlternativeSecurityId", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public class AlternativeSecurityId : IExtensibleDataObject
        {
            public ExtensionDataObject ExtensionData { get; set; }

            [DataMember]
            public string IdentityProvider { get; set; }

            [DataMember]
            public byte[] Key { get; set; }
            [DataMember]
            public int Type { get; set; }
        }

        [DataContract(Name = "DirSyncProvisioningError", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public class DirSyncProvisioningError : IExtensibleDataObject
        {
            public ExtensionDataObject ExtensionData { get; set; }

            [DataMember]
            public string ErrorCategory { get; set; }

            [DataMember]
            public string PropertyName { get; set; }

            [DataMember]
            public string PropertyValue { get; set; }

            [DataMember]
            public DateTime? WhenStarted { get; set; }
        }

        [DataContract(Name = "ValidationError", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public class ValidationError : IExtensibleDataObject
        {
            public ExtensionDataObject ExtensionData { get; set; }

            [DataMember]
            public XmlElement ErrorDetail { get; set; }

            [DataMember]
            public bool Resolved { get; set; }

            [DataMember]
            public string ServiceInstance { get; set; }

            [DataMember]
            public DateTime Timestamp { get; set; }
        }
        [DataContract(Name = "IndirectLicenseError", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public class IndirectLicenseError : IExtensibleDataObject
        {
            public ExtensionDataObject ExtensionData { get; set; }

            [DataMember]
            public AccountSkuIdentifier AccountSku { get; set; }

            [DataMember]
            public string Error { get; set; }

            [DataMember]
            public Guid ReferencedObjectId { get; set; }
        }

        [DataContract(Name = "LicenseAssignmentStatusType", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public enum LicenseAssignmentStatusType
        {
            [EnumMember]
            Active,
            [EnumMember]
            ActiveWithError,
            [EnumMember]
            Error
        }

        [DataContract(Name = "LicenseAssignment", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public class LicenseAssignment : IExtensibleDataObject
        {
            public ExtensionDataObject ExtensionData { get; set; }

            [DataMember]
            public List<string> DisabledServicePlans { get; set; }

            [DataMember]
            public string Error { get; set; }

            [DataMember]
            public Guid ReferencedObjectId { get; set; }

            [DataMember]
            public LicenseAssignmentStatusType Status { get; set; }
        }


        [DataContract(Name = "LicenseAssignmentDetail", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public class LicenseAssignmentDetail : IExtensibleDataObject
        {
            public ExtensionDataObject ExtensionData { get; set; }

            [DataMember]
            public AccountSkuIdentifier AccountSku { get; set; }

            [DataMember]
            public List<LicenseAssignment> Assignments { get; set; }
        }

        [DataContract(Name = "SkuTargetClass", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public enum SkuTargetClass
        {
            [EnumMember]
            NotAvailable,
            [EnumMember]
            User,
            [EnumMember]
            Tenant
        }

        [DataContract(Name = "ServicePlan", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public class ServicePlan : IExtensibleDataObject
        {
            public ExtensionDataObject ExtensionData { get; set; }

            [DataMember]
            public string ServiceName { get; set; }

            [DataMember]
            public Guid? ServicePlanId { get; set; }

            [DataMember]
            public string ServiceType { get; set; }

            [DataMember]
            public SkuTargetClass TargetClass { get; set; }
        }

        [DataContract(Name = "ServiceStatus", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public class ServiceStatus : IExtensibleDataObject
        {
            public ExtensionDataObject ExtensionData { get; set; }

            [DataMember]
            public ProvisioningStatus ProvisioningStatus { get; set; }

            [DataMember]
            public ServicePlan ServicePlan { get; set; }
        }

        [DataContract(Name = "UserLicense", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public class UserLicense : IExtensibleDataObject
        {
            public ExtensionDataObject ExtensionData { get; set; }

            [DataMember]
            public AccountSkuIdentifier AccountSku { get; set; }

            [DataMember]
            public string AccountSkuId { get; set; }

            [DataMember]
            public List<Guid> GroupsAssigningLicense { get; set; }

            [DataMember]
            public List<ServiceStatus> ServiceStatus { get; set; }
        }

        [DataContract(Name = "O365UserReleaseTrack", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public enum O365UserReleaseTrack
        {
            [EnumMember]
            Other,
            [EnumMember]
            StagedRolloutOne,
            [EnumMember]
            StagedRolloutTwo,
            [EnumMember]
            Compass,
            [EnumMember]
            Dogfood
        }

        [DataContract(Name = "StrongAuthenticationMethod", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public class StrongAuthenticationMethod : IExtensibleDataObject
        {
            public ExtensionDataObject ExtensionData { get; set; }

            [DataMember]
            public bool IsDefault { get; set; }

            [DataMember]
            public string MethodType { get; set; }
        }

        [Flags]
        [DataContract(Name = "StrongAuthenticationPhoneAppAuthType", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public enum StrongAuthenticationPhoneAppAuthType
        {
            [EnumMember]
            Notification = 0x1,
            [EnumMember]
            OTP = 0x2
        }

        [DataContract(Name = "StrongAuthenticationPhoneAppNotificationType", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public enum StrongAuthenticationPhoneAppNotificationType
        {
            [EnumMember]
            Unspecified,
            [EnumMember]
            Invalid,
            [EnumMember]
            APNS,
            [EnumMember]
            C2DM,
            [EnumMember]
            GCM,
            [EnumMember]
            MPNS,
            [EnumMember]
            BPS
        }

        [DataContract(Name = "StrongAuthenticationPhoneAppDetail", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public class StrongAuthenticationPhoneAppDetail : IExtensibleDataObject
        {
            public ExtensionDataObject ExtensionData { get; set; }

            [DataMember]
            public StrongAuthenticationPhoneAppAuthType AuthenticationType { get; set; }

            [DataMember]
            public string DeviceName { get; set; }

            [DataMember]
            public string DeviceTag { get; set; }

            [DataMember]
            public string DeviceToken { get; set; }

            [DataMember]
            public StrongAuthenticationPhoneAppNotificationType NotificationType { get; set; }

            [DataMember]
            public string OathSecretKey { get; set; }

            [DataMember]
            public int OathTokenTimeDrift { get; set; }

            [DataMember]
            public string PhoneAppVersion { get; set; }
        }

        [DataContract(Name = "StrongAuthenticationUserDetails", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public class StrongAuthenticationUserDetails : IExtensibleDataObject
        {
            public ExtensionDataObject ExtensionData { get; set; }

            [DataMember]
            public string AlternativePhoneNumber { get; set; }

            [DataMember]
            public string Email { get; set; }

            [DataMember]
            public string OldPin { get; set; }

            [DataMember]
            public string PhoneNumber { get; set; }

            [DataMember]
            public string Pin { get; set; }
        }

        [DataContract(Name = "UserType", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public enum UserType
        {
            [EnumMember]
            Other,
            [EnumMember]
            Member,
            [EnumMember]
            Guest,
            [EnumMember]
            Viral
        }

        [DataContract(Name = "User", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        //[KnownType(typeof(UserExtended))]
        public class User : IExtensibleDataObject
        {

            public ExtensionDataObject ExtensionData { get; set; }

            [DataMember]
            public List<string> AlternateEmailAddresses { get; set; }

            [DataMember]
            public List<string> AlternateMobilePhones { get; set; }

            [DataMember]
            public List<AlternativeSecurityId> AlternativeSecurityIds { get; set; }

            [DataMember]
            public bool? BlockCredential { get; set; }

            [DataMember]
            public string City { get; set; }

            [DataMember]
            public int? CloudExchangeRecipientDisplayType { get; set; }

            [DataMember]
            public string Country { get; set; }

            [DataMember]
            public string Department { get; set; }

            [DataMember]
            public List<DirSyncProvisioningError> DirSyncProvisioningErrors { get; set; }

            [DataMember]
            public string DisplayName { get; set; }

            [DataMember]
            public List<ValidationError> Errors { get; set; }

            [DataMember]
            public string Fax { get; set; }

            [DataMember]
            public string FirstName { get; set; }

            [DataMember]
            public string ImmutableId { get; set; }

            [DataMember]
            public List<IndirectLicenseError> AlternativeSecurityIdsField { get; set; }

            [DataMember]
            public bool? IsBlackberryUser { get; set; }

            [DataMember]
            public bool? IsLicensed { get; set; }

            [DataMember]
            public DateTime? LastDirSyncTime { get; set; }

            [DataMember]
            public string LastName { get; set; }

            [DataMember]
            public DateTime? LastPasswordChangeTimestamp { get; set; }

            [DataMember]
            public List<LicenseAssignmentDetail> LicenseAssignmentDetails { get; set; }

            [DataMember]
            public bool? LicenseReconciliationNeeded { get; set; }

            [DataMember]
            public List<UserLicense> Licenses { get; set; }

            [DataMember]
            public string LiveId { get; set; }

            [DataMember]
            public long? MSExchRecipientTypeDetails { get; set; }

            [DataMember]
            public string MSRtcSipDeploymentLocator { get; set; }

            [DataMember]
            public string MSRtcSipPrimaryUserAddress { get; set; }

            [DataMember]
            public string MobilePhone { get; set; }

            [DataMember]
            public string ObjectId { get; set; }

            [DataMember]
            public string Office { get; set; }

            [DataMember]
            public ProvisioningStatus OverallProvisioningStatus { get; set; }

            [DataMember]
            public bool? PasswordNeverExpires { get; set; }

            [DataMember]
            public bool? PasswordResetNotRequiredDuringActivate { get; set; }

            [DataMember]
            public string PhoneNumber { get; set; }

            [DataMember]
            public XmlElement PortalSettings { get; set; }

            [DataMember]
            public string PostalCode { get; set; }

            [DataMember]
            public string PreferredDataLocation { get; set; }

            [DataMember]
            public string PreferredLanguage { get; set; }

            [DataMember]
            public List<string> ProxyAddresses { get; set; }

            [DataMember]
            public O365UserReleaseTrack? ReleaseTrack { get; set; }

            [DataMember]
            public List<ServiceInformation> ServiceInformation { get; set; }

            [DataMember]
            public string SignInName { get; set; }

            [DataMember]
            public DateTime? SoftDeletionTimestamp { get; set; }

            [DataMember]
            public string State { get; set; }

            [DataMember]
            public string StreetAddress { get; set; }

            [DataMember]
            public List<StrongAuthenticationMethod> StrongAuthenticationMethods { get; set; }

            [DataMember]
            public List<StrongAuthenticationPhoneAppDetail> StrongAuthenticationPhoneAppDetails { get; set; }

            [DataMember]
            public long? StrongAuthenticationProofupTime { get; set; }

            [DataMember]
            public List<StrongAuthenticationRequirement> StrongAuthenticationRequirements { get; set; }

            [DataMember]
            public StrongAuthenticationUserDetails StrongAuthenticationUserDetails { get; set; }

            [DataMember]
            public bool? StrongPasswordRequired { get; set; }

            [DataMember]
            public DateTime? StsRefreshTokensValidFrom { get; set; }

            [DataMember]
            public string Title { get; set; }

            [DataMember]
            public string UsageLocation { get; set; }

            [DataMember]
            public string UserLandingPageIdentifierForO365Shell { get; set; }

            [DataMember]
            public string UserPrincipalName { get; set; }

            [DataMember]
            public string UserThemeIdentifierForO365Shell { get; set; }

            [DataMember]
            public UserType? UserType { get; set; }

            [DataMember]
            public ValidationStatus? ValidationStatus { get; set; }

            [DataMember]
            public DateTime? WhenCreated { get; set; }
        }

        [DataContract(Name = "ListUserResults", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public class ListUserResults : ListResults
        {
            [DataMember]
            public List<User> Results { get; set; }
        }

        [DataContract(Name = "ListUsersResponse", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService")]
        public class ListUsersResponse : Response
        {
            [DataMember]
            public ListUserResults ReturnValue { get; set; }
        }

        [DataContract(Name = "Page", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public enum Page
        {
            [EnumMember]
            First,
            [EnumMember]
            Next,
            [EnumMember]
            Previous,
            [EnumMember]
            Last
        }

        [DataContract(Name = "NavigateUserResultsRequest", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService")]
        public class NavigateUserResultsRequest : Request
        {
            [DataMember]
            public byte[] ListContext { get; set; }

            [DataMember]
            public Page PageToNavigate { get; set; }
        }

        [DataContract(Name = "NavigateUserResultsResponse", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService")]
        public class NavigateUserResultsResponse : Response
        {
            [DataMember]
            public ListUserResults ReturnValue { get; set; }
        }

        #endregion

        #region list user by strong authentication

        [DataContract(Name = "ListUsersByStrongAuthenticationResponse", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService")]
        public class ListUsersByStrongAuthenticationResponse : Response
        {
            [DataMember]
            public ListUserResults ReturnValue { get; set; }
        }

        [DataContract(Name = "ListUsersByStrongAuthenticationRequest", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService")]
        public class ListUsersByStrongAuthenticationRequest : Request
        {
           [DataMember]
            public UserSearchByStrongAuthenticationDefinition UserSearchDefinition { get; set; }
        }

        [DataContract(Name = "UserSearchByStrongAuthenticationDefinition", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public class UserSearchByStrongAuthenticationDefinition : SearchDefinition
        {
            [DataMember]
            public List<string> IncludedProperties { get; set; }

            [DataMember]
            public bool RequirementUnsetOnly { get; set; }

            [DataMember]
            public List<StrongAuthenticationRequirement> Requirements { get; set; }

            [DataMember]
            public Guid? RoleObjectId { get; set; }
        }

        #endregion

        #region dirsyncfeature
        [DataContract(Name = "GetCompanyDirSyncFeaturesRequest", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService")]
        public class GetCompanyDirSyncFeaturesRequest : Request
        {
            [DataMember]
            public string Feature { get; set; }
        }

        [DataContract(Name = "GetCompanyDirSyncFeaturesResponse", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService")]
        public class GetCompanyDirSyncFeaturesResponse : Response
        {
            [DataMember]
            public List<DirSyncFeatureDetails> ReturnValue { get; set; }
        }

        [DataContract(Name = "DirSyncFeatureDetails", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public class DirSyncFeatureDetails : IExtensibleDataObject
        {
            public ExtensionDataObject ExtensionData { get; set; }

            [DataMember]
            public string DirSyncFeature { get; set; }

            [DataMember]
            public bool Enabled { get; set; }
        }


        #endregion

        #region interface
        [DataContract(Name = "GetCompanyInformationResponse", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService")]
        public class GetCompanyInformationResponse : Response
        {
            [DataMember]
            public CompanyInformation ReturnValue { get; set; }
        }
        [DataContract(Name = "ListDomainsRequest", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService")]
        public class ListDomainsRequest : Request
        {
            [DataMember]
            public DomainSearchFilter SearchFilter { get; set; }
        }
        [DataContract(Name = "Version", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration")]
        public enum Version
        {
            [EnumMember]
            FirstVersion = 0,
            [EnumMember]
            Version2 = 1,
            [EnumMember]
            Version3 = 2,
            [EnumMember]
            Version4 = 3,
            [EnumMember]
            Version5 = 4,
            [EnumMember]
            Version6 = 5,
            [EnumMember]
            Version7 = 6,
            [EnumMember]
            Version8 = 7,
            [EnumMember]
            Version9 = 8,
            [EnumMember]
            Version10 = 9,
            [EnumMember]
            Version11 = 10,
            [EnumMember]
            Version12 = 11,
            [EnumMember]
            Version13 = 12,
            [EnumMember]
            Version14 = 13,
            [EnumMember]
            Version15 = 14,
            [EnumMember]
            Version16 = 0xF,
            [EnumMember]
            Version17 = 0x10,
            [EnumMember]
            Version18 = 17,
            [EnumMember]
            Version19 = 18,
            [EnumMember]
            Version20 = 19,
            [EnumMember]
            Version21 = 20,
            [EnumMember]
            Version22 = 21,
            [EnumMember]
            Version23 = 22,
            [EnumMember]
            Version24 = 23,
            [EnumMember]
            Version25 = 24,
            [EnumMember]
            Version26 = 25,
            [EnumMember]
            Version27 = 26,
            [EnumMember]
            Version28 = 27,
            [EnumMember]
            Version29 = 28,
            [EnumMember]
            Version30 = 29,
            [EnumMember]
            Version31 = 30,
            [EnumMember]
            Version32 = 0x1F,
            [EnumMember]
            Version33 = 0x20,
            [EnumMember]
            Version34 = 33,
            [EnumMember]
            Version35 = 34,
            [EnumMember]
            Version36 = 35,
            [EnumMember]
            Version37 = 36,
            [EnumMember]
            Version38 = 37,
            [EnumMember]
            Version39 = 38,
            [EnumMember]
            Version40 = 39,
            [EnumMember]
            Version41 = 40,
            [EnumMember]
            Version42 = 41,
            [EnumMember]
            Version43 = 42,
            [EnumMember]
            Version44 = 43,
            [EnumMember]
            Version45 = 44,
            [EnumMember]
            Version46 = 45,
            [EnumMember]
            Version47 = 46,
            [EnumMember]
            Max = 46
        }

        [DataContract(Name = "Request", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService")]
        public class Request : IExtensibleDataObject
        {
            public Request()
            {
                BecVersion = Version.Version4;
            }
            public ExtensionDataObject ExtensionData { get; set; }

            [DataMember]
            public Version BecVersion { get; set; }

            [DataMember]
            public Guid? TenantId { get; set; }

            [DataMember]
            public string VerifiedDomain { get; set; }
        }

        [ServiceContract(Namespace = "http://provisioning.microsoftonline.com/", ConfigurationName = "IProvisioningWebService")]
        public interface IProvisioningWebService
        {
            [OperationContract(Action = "http://provisioning.microsoftonline.com/IProvisioningWebService/GetCompanyInformation", ReplyAction = "http://provisioning.microsoftonline.com/IProvisioningWebService/GetCompanyInformationResponse")]
            GetCompanyInformationResponse GetCompanyInformation(Request request);
            [OperationContract(Action = "http://provisioning.microsoftonline.com/IProvisioningWebService/ListDomains", ReplyAction = "http://provisioning.microsoftonline.com/IProvisioningWebService/ListDomainsResponse")]
            ListDomainsResponse ListDomains(ListDomainsRequest request);
            [OperationContract(Action = "http://provisioning.microsoftonline.com/IProvisioningWebService/ListRoles", ReplyAction = "http://provisioning.microsoftonline.com/IProvisioningWebService/ListRolesResponse")]
            ListRolesResponse ListRoles(Request request);
            [OperationContract(Action = "http://provisioning.microsoftonline.com/IProvisioningWebService/ListRoleMembers", ReplyAction = "http://provisioning.microsoftonline.com/IProvisioningWebService/ListRoleMembersResponse")]
            ListRoleMembersResponse ListRoleMembers(ListRoleMembersRequest request);

            [OperationContract(Action = "http://provisioning.microsoftonline.com/IProvisioningWebService/ListUsers", ReplyAction = "http://provisioning.microsoftonline.com/IProvisioningWebService/ListUsersResponse")]
            ListUsersResponse ListUsers(ListUsersRequest request);

            [OperationContract(Action = "http://provisioning.microsoftonline.com/IProvisioningWebService/ListUsersByStrongAuthentication", ReplyAction = "http://provisioning.microsoftonline.com/IProvisioningWebService/ListUsersByStrongAuthenticationResponse")]
            ListUsersByStrongAuthenticationResponse ListUsersByStrongAuthentication(ListUsersByStrongAuthenticationRequest request);

            [OperationContract(Action = "http://provisioning.microsoftonline.com/IProvisioningWebService/NavigateUserResults", ReplyAction = "http://provisioning.microsoftonline.com/IProvisioningWebService/NavigateUserResultsResponse")]
            NavigateUserResultsResponse NavigateUserResults(NavigateUserResultsRequest request);

            [OperationContract(Action = "http://provisioning.microsoftonline.com/IProvisioningWebService/GetCompanyDirSyncFeatures", ReplyAction = "http://provisioning.microsoftonline.com/IProvisioningWebService/GetCompanyDirSyncFeaturesResponse")]
            GetCompanyDirSyncFeaturesResponse GetCompanyDirSyncFeatures(GetCompanyDirSyncFeaturesRequest request);

        }
        #endregion

        #region Identity & SOAP headers
        [DataContract(Name = "UserIdentityHeader", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService")]
        public class UserIdentityHeader : IExtensibleDataObject
        {
            public ExtensionDataObject ExtensionData { get; set; }

            [DataMember]
            public string BearerToken { get; set; }

            [DataMember]
            public string LiveToken { get; set; }
        }

        [DataContract(Name = "ClientVersionHeader", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService")]
        public class ClientVersionHeader : IExtensibleDataObject
        {
            public ExtensionDataObject ExtensionData { get; set; }

            [DataMember]
            public Guid ClientId { get; set; }

            [DataMember]
            public string Version { get; set; }
        }
        [DataContract(Name = "ContractVersionHeader", Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService")]
        public class ContractVersionHeader : IExtensibleDataObject
        {
            public ExtensionDataObject ExtensionData { get; set; }

            [DataMember]
            public Version BecVersion { get; set; }
        }

        class BecWebServiceInspector : IClientMessageInspector
        {
            private Token token;
            private int sessionId;
            public BecWebServiceInspector(Token token)
            {
                this.token = token;
            }

            public void AfterReceiveReply(ref Message reply, object correlationState)
            {
                HttpClientHelper.LogSoapEnd(sessionId, reply);
            }

            public object BeforeSendRequest(ref Message request, IClientChannel channel)
            {
                UserIdentityHeader userIdentity = new UserIdentityHeader();
                userIdentity.BearerToken = token.access_token;
                MessageHeader myHeader = MessageHeader.CreateHeader("UserIdentityHeader", "http://provisioning.microsoftonline.com/", userIdentity);
                request.Headers.Add(myHeader);
                ClientVersionHeader clientVersionHeader = new ClientVersionHeader();
                clientVersionHeader.ClientId = new Guid("50afce61-c917-435b-8c6d-60aa5a8b8aa7");
                clientVersionHeader.Version = "1.2.183.81";
                request.Headers.Add(MessageHeader.CreateHeader("ClientVersionHeader", "http://provisioning.microsoftonline.com/", clientVersionHeader));
                ContractVersionHeader contractVersionHeader = new ContractVersionHeader();
                contractVersionHeader.BecVersion = Version.Version47;

                sessionId = HttpClientHelper.LogSoapBegin(request);

                return null;
            }
        }
        class BecWebServiceCustomBehavior : IEndpointBehavior
        {
            public BecWebServiceCustomBehavior(Token token)
            {
                this.Token = token;
            }

            public Token Token { get; private set; }

            public void AddBindingParameters(System.ServiceModel.Description.ServiceEndpoint endpoint, BindingParameterCollection bindingParameters)
            {

            }

            public void ApplyClientBehavior(System.ServiceModel.Description.ServiceEndpoint endpoint, ClientRuntime clientRuntime)
            {
                clientRuntime.MessageInspectors.Add(new BecWebServiceInspector(Token));
            }

            public void ApplyDispatchBehavior(System.ServiceModel.Description.ServiceEndpoint endpoint, EndpointDispatcher endpointDispatcher)
            {

            }

            public void Validate(System.ServiceModel.Description.ServiceEndpoint endpoint)
            {

            }
        }
        #endregion

        delegate T processRequest<T>(IProvisioningWebService service);
        T callSOAP<T>(processRequest<T> processor)
        {
            var token = credential.GetToken<ProvisioningApi>().GetAwaiter().GetResult();
            var binding = new WSHttpBinding(SecurityMode.Transport, reliableSessionEnabled: false);
            binding.Security.Transport.ClientCredentialType = HttpClientCredentialType.None;
            binding.MaxReceivedMessageSize = int.MaxValue;
            binding.MaxBufferPoolSize = int.MaxValue;

            var ep = new EndpointAddress(new Uri(Constants.ProvisionningEndpoint));

            using (var factory = new ChannelFactory<IProvisioningWebService>(binding, ep))
            {
                factory.Endpoint.EndpointBehaviors.Add(new BecWebServiceCustomBehavior(token));

                var serviceProxy = factory.CreateChannel();

                return processor(serviceProxy);
            }
        }
    }
}
