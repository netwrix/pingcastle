using Newtonsoft.Json;
//
// Copyright (c) Vincent LE TOUX for Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Cloud.Common;
using PingCastle.Rules;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Serialization;

namespace PingCastle.Cloud.Data
{
    [DebuggerDisplay("{appDisplayName}")]
    public class HealthCheckCloudDataForwardingMailboxes
    {
        public string ForwardingSmtpAddress { get; set; }
        public string PrimarySmtpAddress { get; set; }
    }

    [DebuggerDisplay("{appDisplayName}")]
    public class HealthCheckCloudDataApplication
    {
        public string appId { get; set; }
        public string appDisplayName { get; set; }
        public string appOwnerTenantId { get; set; }
        public List<HealthCheckCloudDataApplicationOAuth2PermissionGrant> DelegatedPermissions { get; set; }
        public List<HealthCheckCloudDataApplicationRoleAssignedTo> ApplicationPermissions { get; set; }
        public List<HealthCheckCloudDataApplicationMemberOf> MemberOf { get; set; }
        public string objectId { get; set; }
    }

    [DebuggerDisplay("{permission} {resourceId} {consentType} {principalId}")]
    public class HealthCheckCloudDataApplicationOAuth2PermissionGrant
    {
        public string resourceId { get; set; }
        public string permission { get; set; }
        public string consentType { get; set; }
        public string principalId { get; set; }
        public string principalDisplayName { get; set; }
    }

    [DebuggerDisplay("{permission} {resourceId} {principalType} {resourceDisplayName}")]
    public class HealthCheckCloudDataApplicationRoleAssignedTo
    {
        public string permissionId { get; set; }

        public string resourceDisplayName { get; set; }

        public string resourceId { get; set; }
        public string permission { get; set; }
        public string principalType { get; set; }
    }
    [DebuggerDisplay("{displayName} {roleTemplateId}")]
    public class HealthCheckCloudDataApplicationMemberOf
    {
        public string displayName { get; set; }
        public string roleTemplateId { get; set; }
    }

    [DebuggerDisplay("{ObjectId} {UserPrincipalName}")]
    public class HealthCheckCloudDataUser
    {
        public string ObjectId { get; set; }

        public string UserPrincipalName { get; set; }

        public DateTime? WhenCreated { get; set; }

        public DateTime? LastPasswordChangeTimestamp { get; set; }

        public bool? PasswordNeverExpires { get; set; }

        public bool HasImmutableId { get; set; }
    }

    [DebuggerDisplay("{Name} {IsInitial} {VerificationMethod}")]
    public class HealthCheckCloudDataDomain
    {
        public string Authentication { get; set; }

        public string Capabilities { get; set; }

        public bool IsDefault { get; set; }

        public bool IsInitial { get; set; }

        public string Name { get; set; }

        public string RootDomain { get; set; }

        public string Status { get; set; }

        public string VerificationMethod { get; set; }
    }

    [DebuggerDisplay("{Domain} {TenantID} {Region}")]
    public class HealthCheckCloudDataForeignDomains
    {

        public string Domain { get; set; }

        public int GuestsCount { get; set; }

        public string Region { get; set; }

        public string TenantID { get; set; }

        public int MemberCount { get; set; }
    }

    [DebuggerDisplay("{Name} {Type} {Definition}")]
    public class HealthCheckCloudDataNetworkPolicy
    {

        public string Name { get; set; }

        public string Type { get; set; }

        public string Definition { get; set; }

        public bool Trusted { get; set; }
        public bool ApplyToUnknownCountry { get; set; }
    }

    [DebuggerDisplay("{TenantId}")]
    public class HealthCheckCloudDataCrossTenantPolicy
    {

        public string TenantId { get; set; }

        public string lastModified { get; set; }

        public bool? AllowB2BFrom { get; set; }

        public bool? AllowNativeFederationFrom { get; set; }
        public bool? AllowB2BTo { get; set; }

        public bool? AllowNativeFederationTo { get; set; }

    }

    [DebuggerDisplay("{TenantID} {Name} {CountryCode}")]
    public class HealthCheckCloudDataTenantInformation
    {
        public string TenantID { get; set; }

        public string TenantCategory { get; set; }

        public string Name { get; set; }

        public string CountryCode { get; set; }

        public List<string> Domains { get; set; }
    }

    [DebuggerDisplay("{ObjectId} {EmailAddress} {DisplayName}")]
    public class HealthCheckCloudDataRoleMember
    {


        public string ObjectId { get; set; }

        public string EmailAddress { get; set; }

        public string DisplayName { get; set; }

        public DateTime? LastDirSyncTime { get; set; }

        public bool? IsLicensed { get; set; }

        public string OverallProvisioningStatus { get; set; }

        public string RoleMemberType { get; set; }

        public string ValidationStatus { get; set; }

        public bool? PasswordNeverExpires { get; set; }

        public DateTime? LastPasswordChangeTimestamp { get; set; }

        public DateTime? WhenCreated { get; set; }

        public bool HasImmutableId { get; set; }
        public List<string> MFAStatus { get; set; }
    }

    [DebuggerDisplay("{ObjectId} {Name} {Description}")]
    public class HealthCheckCloudDataRole
    {

        public Guid? ObjectId { get; set; }

        public bool? IsSystem { get; set; }

        public string Name { get; set; }

        public bool? IsEnabled { get; set; }

        public string Description { get; set; }

        public int NumMembers { get; set; }
        public List<HealthCheckCloudDataRoleMember> members { get; set; }
        public int NumNoMFA { get; set; }
    }

    [DebuggerDisplay("{RiskId} {Rationale}")]
    public class HealthCheckCloudDataRiskRule : IRuleScore
    {
        public int Points { get; set; }

        // we are using a xml serialization trick to be resilient if a new RiskRuleCategory is added in the future
        public string RiskId { get; set; }

        public string Rationale { get; set; }

        public List<string> Details { get; set; }

        public List<ExtraDetail> ExtraDetails { get; set; }

        public RiskRuleCategory Category { get; set; }
        public RiskModelCategory Model { get; set; }
    }
    public class HealthCheckCloudData : JsonSerialization<HealthCheckCloudData>, IRiskEvaluation
    {

        public DateTime GenerationDate { get; set; }

        public string EngineVersion { get; set; }

        public string IntegrityRules { get; set; }

        [IgnoreDataMember]
        [JsonIgnore]
        public bool IntegrityVerified { get; set; }

        public void SetIntegrity()
        {
            IntegrityRules = ComputeIntegrity();
        }

        public void CheckIntegrity()
        {
            if (new Version(EngineVersion.Split(' ')[0]) > new Version(3, 0))
            {
                var expected = ComputeIntegrity();
                IntegrityVerified = IntegrityRules == expected;
            }
            else
            {
                IntegrityVerified = true;
            }
        }

        string ComputeIntegrity()
        {
            List<string> integrityBase = new List<string>();
            if (RiskRules != null)
            {
                foreach (var r in RiskRules)
                    integrityBase.Add(r.RiskId.Replace("-", "").Replace(".", ""));
                integrityBase.Sort();
            }
            using (var hash = SHA256.Create())
            {
                string s = string.Join(",", integrityBase.ToArray());
                var h = hash.ComputeHash(Encoding.UTF8.GetBytes(s));
                var o = Convert.ToBase64String(h);
                return o;
            }
        }


        public string TenantName { get; set; }

        public string TenantId { get; set; }

        public DateTime TenantCreation { get; set; }


        public string Region { get; set; }
        // from JWT : onprem_sid

        public string DomainSID { get; set; }

        public string ProvisionDisplayName { get; set; }

        public string ProvisionStreet { get; set; }

        public string ProvisionCity { get; set; }

        public string ProvisionPostalCode { get; set; }

        public string ProvisionCountry { get; set; }

        public string ProvisionState { get; set; }

        public string ProvisionTelephoneNumber { get; set; }

        public string ProvisionCountryLetterCode { get; set; }

        public string ProvisionInitialDomain { get; set; }

        public DateTime? ProvisionLastDirSyncTime { get; set; }

        public DateTime? ProvisionLastPasswordSyncTime { get; set; }

        public bool ProvisionSelfServePasswordResetEnabled { get; set; }

        public List<string> ProvisionTechnicalNotificationEmails { get; set; }

        public List<string> ProvisionMarketingNotificationEmails { get; set; }

        public List<string> ProvisionSecurityComplianceNotificationEmails { get; set; }

        public string ProvisionDirSyncApplicationType { get; set; }

        public string ProvisionDirSyncClientMachineName { get; set; }

        public string ProvisionDirSyncClientVersion { get; set; }

        public string ProvisionDirSyncServiceAccount { get; set; }

        public string ProvisionDirectorySynchronizationStatus { get; set; }

        public bool? ProvisionPasswordSynchronizationEnabled { get; set; }

        public List<string> ProvisionAuthorizedServiceInstances { get; set; }


        public List<HealthCheckCloudDataDomain> Domains { get; set; }

        public List<HealthCheckCloudDataRole> Roles { get; set; }

        public int NumberOfUsers { get; set; }
        public List<HealthCheckCloudDataUser> UsersInactive { get; set; }
        public List<HealthCheckCloudDataUser> UsersPasswordNeverExpires { get; set; }

        public List<HealthCheckCloudDataUser> OldInvitations { get; internal set; }

        public List<HealthCheckCloudDataForeignDomains> ForeignDomains { get; set; }
        public List<HealthCheckCloudDataCrossTenantPolicy> CrossTenantPolicies { get; set; }
        public List<HealthCheckCloudDataNetworkPolicy> NetworkPolicies { get; set; }

        public int NumberofGuests { get; set; }

        public int NumberofMembers { get; set; }

        public int NumberofExternalMembers { get; set; }

        public int NumberofInternalMembers { get; set; }

        public int NumberofPureAureInternalMembers { get; set; }

        public int NumberofSyncInternalMembers { get; set; }

        public List<HealthCheckCloudDataTenantInformation> ExternalTenantInformation { get; set; }


        public bool? AzureADConnectDirSyncConfigured { get; set; }
        public bool? AzureADConnectDirSyncEnabled { get; set; }
        public int   AzureADConnectFederatedDomainCount { get; set; }
        public int?   AzureADConnectNumberOfHoursFromLastSync { get; set; }
        public bool? AzureADConnectPassThroughAuthenticationEnabled { get; set; }
        public bool? AzureADConnectSeamlessSingleSignOnEnabled { get; set; }
        public int   AzureADConnectVerifiedCustomDomainCount { get; set; }
        public int   AzureADConnectVerifiedDomainCount { get; set; }

        public string OnPremiseDomainSid { get; set; }
        public List<HealthCheckCloudDataApplication> Applications { get; set; }
        public bool UsersPermissionToCreateGroupsEnabled { get; set; }
        public bool UsersPermissionToCreateLOBAppsEnabled { get; set; }
        public bool UsersPermissionToReadOtherUsersEnabled { get; set; }
        public bool UsersPermissionToUserConsentToAppEnabled { get; set; }

        public string PolicyGuestUserRoleId { get; set; }
        public bool? PolicyAllowEmailVerifiedUsersToJoinOrganization { get; set; }

        public List<HealthCheckCloudDataForwardingMailboxes> ForwardingMailboxes { get; set; }
        public int GlobalScore { get; set; }
        public int StaleObjectsScore { get; set; }
        public int PrivilegiedGroupScore { get; set; }
        public int TrustScore { get; set; }
        public int AnomalyScore { get; set; }

        public int MaturityLevel { get; set; }
        public List<HealthCheckCloudDataRiskRule> RiskRules { get; set; }

        [IgnoreDataMember]
        [XmlIgnore]
        [JsonIgnore]
        public IList<IRuleScore> AllRiskRules { get { return RiskRules.ConvertAll(x => { return (IRuleScore)x; }); } }
    }
}
