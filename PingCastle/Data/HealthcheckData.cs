//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Data;
using PingCastle.Rules;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Xml.Serialization;

namespace PingCastle.Healthcheck
{

    public interface IGPOReference
    {
        string GPOName { get; set; }
        string GPOId { get; set; }
    }

    [DebuggerDisplay("{Name}")]
    public class HealthCheckCertificateTemplate
    {
        [XmlAttribute]
        public string Name { get; set; }

        public List<string> CA { get; set; }

        [XmlAttribute]
        public int Flags { get; set; }

        [XmlAttribute]
        public string OID { get; set; }

        [XmlAttribute]
        public bool CAManagerApproval { get; set; }

        [XmlAttribute]
        public int EnrolleeSupplies { get; set; }

        public List<string> EnrollmentLowPrivilegePrincipals { get; set; }

        [XmlAttribute]
        public bool IssuanceRequirementsEmpty { get; set; }

        [XmlAttribute]
        public bool VulnerableTemplateACL { get; set; }

        [XmlAttribute]
        public bool LowPrivCanEnroll { get; set; }

        [XmlAttribute]
        public bool EnrollmentAgentTemplate { get; set; }

        [XmlAttribute]
        public bool HasAnyPurpose { get; set; }

        [XmlAttribute]
        public bool HasAuthenticationEku { get; set; }
        public List<HealthcheckDelegationData> Delegations { get; set; }

        [XmlAttribute]
        public bool NoSecurityExtension { get; set; }

        [XmlAttribute]
        public bool IsAuthorisedSignaturesRequired { get; set; }

        [XmlAttribute]
        public bool AllowsToSupplySubjectInRequest { get; set; }

        [XmlAttribute]
        public DateTime WhenChanged { get; set; }

        [XmlAttribute]
        public int SchemaVersion { get; set; }

        [XmlAttribute]
        public List<string> EKUs { get; set; }

        [XmlAttribute]
        public string Owner { get; set; }

        public List<HealthCheckCertificateTemplateRights> Rights { get; set; }
    }

    public class HealthCheckCertificateTemplateRights
    {
        [XmlAttribute]
        public string Account { get; set; }
        [XmlAttribute]
        public List<string> Rights { get; set; }
    }

    public class HealthCheckCertificateAuthorityData
    {
        [XmlAttribute]
        public string Name { get; set; }

        [XmlAttribute]
        public string DnsHostName { get; set; }

        [XmlIgnore]
        public string FullName => $"{DnsHostName}\\{Name}";
                       
        [DefaultValue(null)]
        public bool? IsLowPrivilegedPrincipalOwner { get; set; }

        public List<byte[]> CertificatesData { get; set; }

        [XmlAttribute]
        public List<string> LowPrivelegedEnrollPrincipals { get; set; }

        [XmlAttribute]
        public List<string> LowPrivelegedManagerPrincipals { get; set; }
       
        [XmlAttribute]
        public string EnrollmentRestrictions { get; set; }
    }

    [DebuggerDisplay("{Name}")]
    public class HealthCheckCertificateEnrollment
    {
        [XmlAttribute]
        public string Name { get; set; }

        [XmlAttribute]
        public string OID { get; set; }

        public List<string> SSLProtocol { get; set; }

        [XmlAttribute]
        public bool WebEnrollmentHttps { get; set; }

        [XmlAttribute]
        public bool WebEnrollmentHttp { get; set; }

        [XmlAttribute]
        public bool WebEnrollmentChannelBindingDisabled { get; set; }

        [XmlAttribute]
        public bool CESHttp { get; set; }

        [XmlAttribute]
        public bool CESHttps { get; set; }

        [XmlAttribute]
        public bool CESChannelBindingDisabled { get; set; }

    }

    [DebuggerDisplay("{Name}")]
    public class HealthCheckSCCMServer
    {
        [XmlAttribute]
        public string Name { get; set; }

        public string Capabilities { get; set; }

        [XmlAttribute]
        public string MPName { get; set; }

        [XmlAttribute]
        public int Version { get; set; }
    }

    [DebuggerDisplay("{DN} {ClassName} {DNS}")]
    public class HealthCheckServicePoint
    {
        [XmlAttribute]
        public string DN { get; set; }

        [XmlAttribute]
        public string ClassName { get; set; }
        [XmlAttribute]
        public string DNS { get; set; }
        public List<string> BindingInfo { get; set; }
    }

    public class HealthCheckDisplaySpecifier
    {
        [XmlAttribute]
        public string DN { get; set; }

        public string AdminContextMenu { get; set; }

        public DateTime WhenChanged { get; set; }
    }

    [DebuggerDisplay("{DN} {ClassName} {DNS}")]
    public class HealthCheckMSOL
    {
        [XmlAttribute]
        public string Account { get; set; }
        [XmlAttribute]
        public string Identifier { get; set; }
        [XmlAttribute]
        public string Computer { get; set; }
        [XmlAttribute]
        public string Tenant { get; set; }
        [XmlAttribute]
        public string MSOLDN { get; set; }
        [XmlAttribute]
        public DateTime MSOLCreated { get; set; }
        [XmlAttribute]
        public DateTime MSOLLastLogon { get; set; }
        [XmlAttribute]
        public bool MSOLIsEnabled { get; set; }
        [XmlAttribute]
        public DateTime MSOLPwdLastSet { get; set; }
        [XmlAttribute]
        public DateTime ComputerPwdLastSet { get; set; }
        [XmlAttribute]
        public bool ComputerIsEnabled { get; set; }
        [XmlAttribute]
        public DateTime ComputerLastLogon { get; set; }
        [XmlAttribute]
        public DateTime ComputerCreated { get; set; }
        [XmlAttribute]
        public string ComputerDN { get; set; }
    }

    [DebuggerDisplay("{Name}")]
    public class HealthCheckGroupMemberData
    {
        public string Name { get; set; }

        public bool IsExternal { get; set; }

        public string DistinguishedName { get; set; }

        public bool IsEnabled { get; set; }

        public bool IsActive { get; set; }

        public bool IsLocked { get; set; }

        public bool DoesPwdNeverExpires { get; set; }

        public bool CanBeDelegated { get; set; }

        public DateTime LastLogonTimestamp { get; set; }

        public DateTime PwdLastSet { get; set; }

        public bool SmartCardRequired { get; set; }

        public bool IsService { get; set; }

        public DateTime Created { get; set; }

        public bool IsInProtectedUser { get; set; }

        public string Email { get; set; }

        public string Class { get; set; }

        public string Sid { get; set; }
    }

    [DebuggerDisplay("{GroupName}")]
    public class HealthCheckGroupData
    {
        public HealthCheckGroupData()
        {
            Level = PingCastleReportDataExportLevel.Full;
        }

        [IgnoreDataMember]
        [XmlIgnore]
        public PingCastleReportDataExportLevel Level { get; set; }

        public string GroupName { get; set; }

        public string DistinguishedName { get; set; }

        public int NumberOfMember { get; set; }

        public int NumberOfMemberDisabled { get; set; }

        public int NumberOfMemberPwdNotRequired { get; set; }

        public int NumberOfMemberPwdNeverExpires { get; set; }

        public int NumberOfMemberLocked { get; set; }

        public int NumberOfMemberInactive { get; set; }

        public int NumberOfMemberActive { get; set; }

        public int NumberOfMemberEnabled { get; set; }

        public int NumberOfMemberCanBeDelegated { get; set; }

        public int NumberOfExternalMember { get; set; }

        public int NumberOfSmartCardRequired { get; set; }

        public int NumberOfServiceAccount { get; set; }

        public int NumberOfMemberInProtectedUsers { get; set; }

        public string Sid { get; set; }

        public bool ShouldSerializeMembers() { return (int)Level <= (int)PingCastleReportDataExportLevel.Full; }
        public List<HealthCheckGroupMemberData> Members { get; set; }

    }

    [DebuggerDisplay("FQDN: {DnsName} SiD: {Sid} NetBIOS: {NetbiosName} Forest: FQDN: {ForestName} SID: {ForestSid} NetBIOS {ForestNetbios}")]
    public class HealthCheckTrustDomainInfoData
    {
        public string DnsName { get; set; }
        public string NetbiosName { get; set; }
        public string Sid { get; set; }
        public DateTime CreationDate { get; set; }
        public string ForestName { get; set; }
        public string ForestSid { get; set; }
        public string ForestNetbios { get; set; }

        private DomainKey _domain;
        [IgnoreDataMember]
        [XmlIgnore]
        public DomainKey Domain
        {
            get
            {
                if (_domain == null)
                {
                    _domain = DomainKey.Create(DnsName, Sid, NetbiosName);
                }
                return _domain;
            }
            set
            {
                _domain = value;
            }
        }

        private bool _forestSet = false;
        private DomainKey _forest;
        [IgnoreDataMember]
        [XmlIgnore]
        public DomainKey Forest
        {
            get
            {
                if (!_forestSet)
                {
                    _forestSet = true;
                    if (String.Equals(DnsName, ForestName, StringComparison.InvariantCultureIgnoreCase))
                        _forest = Domain;
                    else
                    {
                        _forest = DomainKey.Create(ForestName, ForestSid, ForestNetbios);
                    }
                }
                return _forest;
            }
            set
            {
                _forest = value;
            }
        }

    }

    [DebuggerDisplay("{TrustPartner} {CreationDate}")]
    public class HealthCheckTrustData
    {
        ///<summary>
        ///TrustPartner is garanteed to be in lowercase.
        ///</summary>
        public string TrustPartner { get; set; }

        public int TrustAttributes { get; set; }

        public int TrustDirection { get; set; }

        public int TrustType { get; set; }

        public DateTime CreationDate { get; set; }

        public bool IsActive { get; set; }

        public string SID { get; set; }

        public string NetBiosName { get; set; }

        public int msDSSupportedEncryptionTypes { get; set; }

        public List<HealthCheckTrustDomainInfoData> KnownDomains { get; set; }

        private DomainKey _domain;
        [IgnoreDataMember]
        [XmlIgnore]
        public DomainKey Domain
        {
            get
            {
                if (_domain == null)
                {
                    _domain = DomainKey.Create(TrustPartner, SID, NetBiosName);
                }
                return _domain;
            }
        }
    }

    [DebuggerDisplay("{GPOName} {UserName}")]
    public class GPOInfo : IGPOReference
    {
        public string GPOName { get; set; }
        public string GPOId { get; set; }
        public bool IsDisabled { get; set; }
        public List<string> AppliedTo { get; set; }
        public List<int> AppliedOrder { get; set; }
    }

    [DebuggerDisplay("{GPOName} {UserName}")]
    public class GPPPassword : IGPOReference
    {
        public string UserName { get; set; }
        public string Other { get; set; }
        public string Password { get; set; }
        public DateTime Changed { get; set; }


        public string Type { get; set; }

        public string GPOName { get; set; }
        public string GPOId { get; set; }
    }

    [DebuggerDisplay("{GPOName} {FileName}")]
    public class GPPFileDeployed : IGPOReference
    {
        public string FileName { get; set; }
        public string Type { get; set; }
        public string GPOName { get; set; }
        public string GPOId { get; set; }
        public List<HealthcheckScriptDelegationData> Delegation { get; set; }
    }

    // from: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpfas/2efe0b76-7b4a-41ff-9050-1023f8196d16
    [DebuggerDisplay("{GPOName} {Name} {Direction} {Action}")]
    public class GPPFireWallRule : IGPOReference
    {
        public string GPOName { get; set; }
        public string GPOId { get; set; }

        [XmlAttribute]
        [DefaultValue(null)]
        public string Id { get; set; }

        public List<string> RA4 { get; set; }
        public List<string> RA6 { get; set; }
        public List<string> LA4 { get; set; }
        public List<string> LA6 { get; set; }

        [XmlAttribute]
        [DefaultValue(null)]
        public string LPort { get; set; }

        [XmlAttribute]
        [DefaultValue(null)]
        public string RPort { get; set; }

        [XmlAttribute]
        [DefaultValue(null)]
        public string Version { get; set; }

        [XmlAttribute]
        [DefaultValue(null)]
        public string Name { get; set; }

        [DefaultValue(null)]
        public int? Protocol { get; set; }

        [XmlAttribute]
        [DefaultValue(false)]
        public bool Active { get; set; }

        [XmlAttribute]
        [DefaultValue(null)]
        public string Direction { get; set; }

        [XmlAttribute]
        [DefaultValue(null)]
        public string Action { get; set; }

        [XmlAttribute]
        [DefaultValue(null)]
        public string App { get; set; }
    }

    [DebuggerDisplay("{GPOName}")]
    public class GPPTerminalServiceConfig : IGPOReference
    {
        public string GPOName { get; set; }
        public string GPOId { get; set; }

        [DefaultValue(null)]
        public int? MaxIdleTime { get; set; }

        [DefaultValue(null)]
        public int? MaxDisconnectionTime { get; set; }

        [DefaultValue(null)]
        public bool? fDisableCpm { get; set; }
    }

    [DebuggerDisplay("{Property} {Value}")]
    public class GPPSecurityPolicyProperty
    {
        public GPPSecurityPolicyProperty()
        {
        }
        public GPPSecurityPolicyProperty(string property, int value)
        {
            this.Property = property;
            this.Value = value;
        }
        public string Property { get; set; }
        public int Value { get; set; }
    }

    [DebuggerDisplay("{Expected} {Found}")]
    public class HealthcheckOUChangedData
    {
        [XmlAttribute]
        public string Expected { get; set; }
        [XmlAttribute]
        public string Found { get; set; }
    }

    [DebuggerDisplay("{GPOName}")]
    public class GPPSecurityPolicy : IGPOReference
    {
        public List<GPPSecurityPolicyProperty> Properties { get; set; }

        public string GPOName { get; set; }
        public string GPOId { get; set; }
    }

    [DebuggerDisplay("{GPOName} {User} {Privilege}")]
    public class GPPRightAssignment : IGPOReference
    {
        public string User { get; set; }

        public string Privilege { get; set; }

        public string GPOName { get; set; }
        public string GPOId { get; set; }
    }

    [DebuggerDisplay("{GPOName} {User} {Privilege}")]
    public class GPOMembership : IGPOReference
    {
        public string GPOName { get; set; }
        public string GPOId { get; set; }
        public string User { get; set; }
        public string MemberOf { get; set; }
    }

    [DebuggerDisplay("{GPOName} {Order} {Server}")]
    public class GPOEventForwardingInfo : IGPOReference
    {
        public string GPOName { get; set; }
        public string GPOId { get; set; }
        public int Order { get; set; }
        public string Server { get; set; }
    }

    [DebuggerDisplay("{GPOName}")]
    public class GPPHardenedPath : IGPOReference
    {
        [XmlAttribute]
        public string Key { get; set; }

        [DefaultValue(null)]
        public bool? RequireMutualAuthentication { get; set; }
        [DefaultValue(null)]
        public bool? RequireIntegrity { get; set; }
        [DefaultValue(null)]
        public bool? RequirePrivacy { get; set; }

        [XmlAttribute]
        public string GPOName { get; set; }

        [XmlAttribute]
        public string GPOId { get; set; }
    }

    [DebuggerDisplay("{Name}")]
    public class HealthcheckAccountDetailData
    {
        public string DistinguishedName { get; set; }

        public string Name { get; set; }

        public DateTime LastLogonDate { get; set; }

        public DateTime CreationDate { get; set; }

        public DateTime PwdLastSet { get; set; }

        public bool ShouldSerializeEvent() { return Event != DateTime.MinValue; }
        public DateTime Event { get; set; }
    }

    public interface IAddAccountData
    {
        void AddWithoutDetail(string property);
        void AddDetail(string property, HealthcheckAccountDetailData data);
        void AddSIDHistoryDetail(HealthcheckAccountDetailData item, PingCastle.ADWS.ADItem x);
    }

    public class ProxyHealthcheckAccountData : IAddAccountData
    {
        public ProxyHealthcheckAccountData()
        {
            Clients = new List<IAddAccountData>();
        }
        public List<IAddAccountData> Clients { get; private set; }

        public void AddWithoutDetail(string property)
        {
            foreach (var c in Clients) c.AddWithoutDetail(property);
        }

        public void AddDetail(string property, HealthcheckAccountDetailData data)
        {
            foreach (var c in Clients) c.AddDetail(property, data);
        }

        public void AddSIDHistoryDetail(HealthcheckAccountDetailData item, ADWS.ADItem x)
        {
            foreach (var c in Clients) c.AddSIDHistoryDetail(item, x);
        }
    }

    public class HealthcheckAccountData : IAddAccountData
    {
        public HealthcheckAccountData()
        {
            Level = PingCastleReportDataExportLevel.Full;
        }

        // for statics in the report generation
        public void Add(HealthcheckAccountData x)
        {
            Number += x.Number;
            NumberActive += x.NumberActive;
            NumberBadPrimaryGroup += x.NumberBadPrimaryGroup;
            NumberDesEnabled += x.NumberDesEnabled;
            NumberNotAesEnabled += x.NumberNotAesEnabled;
            NumberDisabled += x.NumberDisabled;
            NumberEnabled += x.NumberEnabled;
            NumberAccessDenied += x.NumberAccessDenied;
            NumberInactive += x.NumberInactive;
            NumberLocked += x.NumberLocked;
            NumberPwdNeverExpires += x.NumberPwdNeverExpires;
            NumberPwdNotRequired += x.NumberPwdNotRequired;
            NumberReversibleEncryption += x.NumberReversibleEncryption;
            NumberSidHistory += x.NumberSidHistory;
            NumberTrustedToAuthenticateForDelegation += x.NumberTrustedToAuthenticateForDelegation;
            NumberDuplicate += x.NumberDuplicate;
            NumberNoPreAuth += x.NumberNoPreAuth;
        }

        [IgnoreDataMember]
        [XmlIgnore]
        public PingCastleReportDataExportLevel Level { get; set; }

        [IgnoreDataMember]
        [XmlIgnore]
        public bool DotNotRecordDetail { get; set; }

        public int Number { get; set; }

        public int NumberAccessDenied { get; set; }

        public int NumberEnabled { get; set; }

        public int NumberDisabled { get; set; }

        public int NumberActive { get; set; }

        public int NumberInactive { get; set; }

        public bool ShouldSerializeListInactive() { return (int)Level <= (int)PingCastleReportDataExportLevel.Full; }
        public List<HealthcheckAccountDetailData> ListInactive { get; set; }

        public int NumberLocked { get; set; }

        public bool ShouldSerializeListLocked() { return (int)Level <= (int)PingCastleReportDataExportLevel.Full; }
        public List<HealthcheckAccountDetailData> ListLocked { get; set; }

        public int NumberPwdNeverExpires { get; set; }

        public bool ShouldSerializeListPwdNeverExpires() { return (int)Level <= (int)PingCastleReportDataExportLevel.Full; }
        public List<HealthcheckAccountDetailData> ListPwdNeverExpires { get; set; }

        public int NumberSidHistory { get; set; }

        public bool ShouldSerializeListSidHistory() { return (int)Level <= (int)PingCastleReportDataExportLevel.Full; }
        public List<HealthcheckAccountDetailData> ListSidHistory { get; set; }

        public bool ShouldSerializeListDomainSidHistory() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public List<HealthcheckSIDHistoryData> ListDomainSidHistory { get; set; }

        public int NumberPwdNotRequired { get; set; }

        public bool ShouldSerializeListPwdNotRequired() { return (int)Level <= (int)PingCastleReportDataExportLevel.Full; }
        public List<HealthcheckAccountDetailData> ListPwdNotRequired { get; set; }

        public int NumberBadPrimaryGroup { get; set; }

        public bool ShouldSerializeListBadPrimaryGroup() { return (int)Level <= (int)PingCastleReportDataExportLevel.Full; }
        public List<HealthcheckAccountDetailData> ListBadPrimaryGroup { get; set; }

        public int NumberDesEnabled { get; set; }

        public bool ShouldSerializeListDesEnabled() { return (int)Level <= (int)PingCastleReportDataExportLevel.Full; }
        public List<HealthcheckAccountDetailData> ListDesEnabled { get; set; }

        public int NumberNotAesEnabled { get; set; }

        public bool ShouldSerializeListNotAesEnabled() { return (int)Level <= (int)PingCastleReportDataExportLevel.Full; }
        public List<HealthcheckAccountDetailData> ListNotAesEnabled { get; set; }

        public int NumberTrustedToAuthenticateForDelegation { get; set; }

        public bool ShouldSerializeListTrustedToAuthenticateForDelegation() { return (int)Level <= (int)PingCastleReportDataExportLevel.Full; }
        public List<HealthcheckAccountDetailData> ListTrustedToAuthenticateForDelegation { get; set; }

        public int NumberReversibleEncryption { get; set; }

        public bool ShouldSerializeListReversibleEncryption() { return (int)Level <= (int)PingCastleReportDataExportLevel.Full; }
        public List<HealthcheckAccountDetailData> ListReversibleEncryption { get; set; }

        public int NumberDuplicate { get; set; }

        public bool ShouldSerializeListDuplicate() { return (int)Level <= (int)PingCastleReportDataExportLevel.Full; }
        public List<HealthcheckAccountDetailData> ListDuplicate { get; set; }

        public int NumberNoPreAuth { get; set; }
        public bool ShouldSerializeListNoPreAuth() { return (int)Level <= (int)PingCastleReportDataExportLevel.Full; }
        public List<HealthcheckAccountDetailData> ListNoPreAuth { get; set; }

        public int NumberLAPS { get; set; }
        public int NumberLAPSNew { get; set; }
        public int NumberLAPSBoth { get; set; }

        public void AddDetail<T>(string property, T item)
        {
            if (!DotNotRecordDetail)
            {
                var p = this.GetType().GetProperty("List" + property);
                List<T> l = (List<T>)p.GetValue(this, null);
                if (l == null)
                {
                    l = new List<T>();
                    p.SetValue(this, l, null);
                }
                l.Add(item);
            }
            AddWithoutDetail(property);
        }

        public void AddDetail(string property, HealthcheckAccountDetailData item)
        {
            AddDetail<HealthcheckAccountDetailData>(property, item);
        }

        public void AddSIDHistoryDetail(HealthcheckAccountDetailData item, PingCastle.ADWS.ADItem x)
        {
            NumberSidHistory++;
            if (DotNotRecordDetail)
                return;
            if (ListSidHistory == null)
                ListSidHistory = new List<HealthcheckAccountDetailData>();
            ListSidHistory.Add(item);
            // sum up the count of sid history per remote domain
            foreach (SecurityIdentifier sid in x.SIDHistory)
            {
                if (ListDomainSidHistory == null)
                    ListDomainSidHistory = new List<HealthcheckSIDHistoryData>();
                SecurityIdentifier domainSid = sid.AccountDomainSid;
                bool dangerousSID = false;
                // special case when SIDHistory has been modified ...
                if (domainSid == null)
                {
                    domainSid = sid;
                    dangerousSID = true;
                }
                else
                {
                    var sidparts = sid.Value.Split('-');
                    if (sidparts.Length > 1)
                    {
                        var lastPart = int.Parse(sidparts[sidparts.Length - 1]);
                        if (lastPart < 1000)
                            dangerousSID = true;
                    }
                }
                bool found = false;
                foreach (HealthcheckSIDHistoryData domainSIDHistory in ListDomainSidHistory)
                {
                    if (domainSIDHistory.DomainSid == domainSid.Value)
                    {
                        domainSIDHistory.Count++;
                        found = true;

                        if ((domainSIDHistory.FirstDate > x.WhenCreated && x.WhenCreated != DateTime.MinValue) || domainSIDHistory.FirstDate == DateTime.MinValue)
                            domainSIDHistory.FirstDate = x.WhenCreated;
                        if (domainSIDHistory.LastDate < x.WhenCreated)
                            domainSIDHistory.LastDate = x.WhenCreated;
                        if (dangerousSID)
                            domainSIDHistory.DangerousSID = dangerousSID;
                        break;
                    }
                }
                if (!found)
                {
                    HealthcheckSIDHistoryData domainSIDHistory = new HealthcheckSIDHistoryData();
                    ListDomainSidHistory.Add(domainSIDHistory);
                    domainSIDHistory.DomainSid = domainSid.Value;
                    domainSIDHistory.Count = 1;
                    domainSIDHistory.LastDate = x.WhenCreated;
                    domainSIDHistory.FirstDate = x.WhenCreated;
                    domainSIDHistory.DangerousSID = dangerousSID;
                }
            }
        }


        public void AddWithoutDetail(string property)
        {
            var p = this.GetType().GetProperty("Number" + property);
            int num = (int)p.GetValue(this, null);
            num++;
            p.SetValue(this, num, null);
        }
    }

    [DebuggerDisplay("{Category} {RiskId} {Rationale}")]
    public class HealthcheckRiskRule : IRuleScore
    {
        public HealthcheckRiskRule()
        {
            Level = PingCastleReportDataExportLevel.Full;
        }

        [IgnoreDataMember]
        [XmlIgnore]
        public PingCastleReportDataExportLevel Level { get; set; }

        public int Points { get; set; }

        // we are using a xml serialization trick to be resilient if a new RiskRuleCategory is added in the future
        [XmlIgnore]
        public RiskRuleCategory Category { get; set; }

        [XmlElement("Category")]
        public string CategoryAsString
        {
            get
            {
                return Category.ToString();
            }
            set
            {
                try
                {
                    Category = (RiskRuleCategory)Enum.Parse(typeof(RiskRuleCategory), value);
                }
                catch
                {
                    Category = RiskRuleCategory.Unknown;
                }
            }
        }

        // we are using a xml serialization trick to be resilient if a new RiskModelCategory is added in the future
        [XmlIgnore]
        public RiskModelCategory Model { get; set; }

        [XmlElement("Model")]
        public string ModelAsString
        {
            get
            {
                return Model.ToString();
            }
            set
            {
                try
                {
                    Model = (RiskModelCategory)Enum.Parse(typeof(RiskModelCategory), value);
                }
                catch
                {
                    Model = RiskModelCategory.Unknown;
                }
            }
        }

        public string RiskId { get; set; }

        public string Notice { get; set; }

        public string NoticeTooltip { get; set; }

        public string Rationale { get; set; }

        public bool ShouldSerializeDetails() { return (int)Level <= (int)PingCastleReportDataExportLevel.Full; }
        public List<string> Details { get; set; }

        public List<ExtraDetail> ExtraDetails { get; set; }
    }

    [DebuggerDisplay("{OperatingSystem}")]
    public class HealthcheckOSData
    {
        public HealthcheckOSData()
        {
        }
        public HealthcheckOSData(string OS)
        {
            this.OperatingSystem = OS;
        }
        public string OperatingSystem { get; set; }
        public int NumberOfOccurence { get; set; }
        public HealthcheckAccountData data { get; set; }
    }

    [DebuggerDisplay("{OSVersion} Server? {IsServer}")]
    public class HealthcheckOSVersionData
    {
        public HealthcheckOSVersionData()
        {
        }
        public HealthcheckOSVersionData(PingCastle.ADWS.ADItem x)
        {
            IsServer = x.OperatingSystem.Contains("Server");
            IsLTSC = x.OperatingSystem.IndexOf("LTSC", StringComparison.OrdinalIgnoreCase) >= 0 || x.OperatingSystem.IndexOf("LTSB", StringComparison.OrdinalIgnoreCase) >= 0;
            IsIOT = x.OperatingSystem.IndexOf(" IOT", StringComparison.OrdinalIgnoreCase) >= 0;
            OSVersion = x.OperatingSystemVersion;
            data = new HealthcheckAccountData();
            data.DotNotRecordDetail = true;
        }
        [XmlAttribute]
        public string OSVersion { get; set; }
        [XmlAttribute]
        [DefaultValue(false)]
        public bool IsServer { get; set; }
        [XmlAttribute]
        [DefaultValue(false)]
        public bool IsLTSC { get; set; }
        [DefaultValue(false)]
        public bool IsIOT { get; set; }
        [XmlAttribute]
        public int NumberOfOccurence { get; set; }
        public HealthcheckAccountData data { get; set; }
    }

    [DebuggerDisplay("{LoginScript}")]
    public class HealthcheckLoginScriptData
    {
        public HealthcheckLoginScriptData()
        {
        }
        public HealthcheckLoginScriptData(string script, int numOccurence)
        {
            this.LoginScript = script;
            this.NumberOfOccurence = numOccurence;
        }
        public string LoginScript { get; set; }
        public int NumberOfOccurence { get; set; }

        public List<HealthcheckScriptDelegationData> Delegation { get; set; }
    }

    [DebuggerDisplay("{GPOName} {Action} {CommandLine}")]
    public class HealthcheckGPOLoginScriptData : IGPOReference
    {

        public string GPOName { get; set; }

        public string GPOId { get; set; }

        public string Action { get; set; }

        public string Source { get; set; }

        public string CommandLine { get; set; }

        public string Parameters { get; set; }

        public List<HealthcheckScriptDelegationData> Delegation { get; set; }
    }

    [DebuggerDisplay("{DistinguishedName} {Account} {Right}")]
    public class HealthcheckDelegationData
    {
        public string DistinguishedName { get; set; }

        public string Account { get; set; }

        public string SecurityIdentifier { get; set; }

        public string Right { get; set; }
    }

    [DebuggerDisplay("{Account} {Right}")]
    public class HealthcheckScriptDelegationData
    {
        public string Account { get; set; }

        public string Right { get; set; }
    }

    [DebuggerDisplay("{GPOName} {Account} {Right}")]
    public class GPODelegationData : IGPOReference
    {
        public string GPOName { get; set; }

        public string GPOId { get; set; }

        public string Item { get; set; }

        public string Account { get; set; }

        public string Right { get; set; }
    }

    [DebuggerDisplay("{GPOName} {Category} {Value}")]
    public class GPOAuditSimpleData : IGPOReference
    {
        public string GPOName { get; set; }

        public string GPOId { get; set; }

        public string Category { get; set; }

        public int Value { get; set; }
    }

    [DebuggerDisplay("{GPOName} {SubCategory} {Value}")]
    public class GPOAuditAdvancedData : IGPOReference
    {
        public string GPOName { get; set; }

        public string GPOId { get; set; }

        public Guid SubCategory { get; set; }

        public int Value { get; set; }
    }

    [DebuggerDisplay("{GPOName} {WSUSserver} {AUOptions} {NoAutoUpdate}")]
    public class HealthcheckWSUSData : IGPOReference
    {
        public string GPOName { get; set; }

        public string GPOId { get; set; }
        [XmlAttribute]
        [DefaultValue(null)]
        public string WSUSserver { get; set; }
        [DefaultValue(null)]
        public byte[] WSUSserverCertificate { get; set; }
        [DefaultValue(null)]
        public List<string> WSUSserverSSLProtocol { get; set; }
        [DefaultValue(null)]
        public List<HealthcheckWSUSDataOption> Options { get; set; }
        [XmlAttribute]
        [DefaultValue(null)]
        public string WSUSserverAlternate { get; set; }
        [DefaultValue(null)]
        public byte[] WSUSserverAlternateCertificate { get; set; }
        [DefaultValue(null)]
        public List<string> WSUSserverAlternateSSLProtocol { get; set; }
    }
    public class HealthcheckWSUSDataOption
    {
        [XmlAttribute]
        public string Name { get; set; }
        [XmlAttribute]
        public int Value { get; set; }
    }

    [DebuggerDisplay("{GPOName} {FileExt} {OpenApp}")]
    public class GPPFolderOption : IGPOReference
    {
        public string GPOName { get; set; }

        public string GPOId { get; set; }
        [XmlAttribute]
        [DefaultValue(null)]
        public string OpenApp { get; set; }

        [XmlAttribute]
        [DefaultValue(null)]
        public string FileExt { get; set; }

        [XmlAttribute]
        [DefaultValue(null)]
        public string Action { get; set; }
    }

    [DebuggerDisplay("{GPOName} {FileExt} {OpenApp}")]
    public class HealthcheckDefenderASRData : IGPOReference
    {
        public string GPOName { get; set; }

        public string GPOId { get; set; }
        [XmlAttribute]
        [DefaultValue(null)]
        public string ASRRule { get; set; }

        [XmlAttribute]
        [DefaultValue(null)]
        public int Action { get; set; }
    }

    [DebuggerDisplay("{new System.Security.Cryptography.X509Certificates.X509Certificate2(Certificate)} Source: {Source}")]
    public class HealthcheckCertificateData
    {
        public string Source { get; set; }
        public string Store { get; set; }
        public byte[] Certificate { get; set; }
    }

    [DebuggerDisplay("{DomainSid} {FriendlyName}")]
    public class HealthcheckSIDHistoryData
    {
        public string DomainSid { get; set; }
        public string FriendlyName { get; set; }
        public string NetBIOSName { get; set; }
        public DateTime FirstDate { get; set; }
        public DateTime LastDate { get; set; }
        public int Count { get; set; }

        public bool DangerousSID { get; set; }

        private DomainKey _domain;
        [IgnoreDataMember]
        [XmlIgnore]
        public DomainKey Domain
        {
            get
            {
                if (_domain == null)
                {
                    _domain = DomainKey.Create(FriendlyName, DomainSid, NetBIOSName);
                }
                return _domain;
            }
        }
    }

    [Flags]
    public enum SMBSecurityModeEnum
    {
        NotTested = 0,
        None = 1,
        SmbSigningEnabled = 2,
        SmbSigningRequired = 4,
    }

    [DebuggerDisplay("{DCName}")]
    public class HealthcheckDCRPCInterface
    {
        [XmlAttribute]
        public string IP { get; set; }

        [XmlAttribute]
        public string Interface { get; set; }

        [XmlAttribute]
        public int OpNum { get; set; }

        [XmlAttribute]
        public string Function { get; set; }
    }

    [DebuggerDisplay("{DCName}")]
    public class HealthcheckDomainController
    {
        public string DCName { get; set; }

        public DateTime CreationDate { get; set; }

        [DefaultValue(null)]
        public bool? IsGlobalCatalog { get; set; }

        [DefaultValue(null)]
        public bool? IsReadOnly { get; set; }

        public DateTime StartupTime { get; set; }

        public DateTime LastComputerLogonDate { get; set; }

        public string DistinguishedName { get; set; }

        public string OperatingSystem { get; set; }
        public string OperatingSystemVersion { get; set; }

        public string OwnerSID { get; set; }

        public string OwnerName { get; set; }

        public bool HasNullSession { get; set; }

        public bool SupportSMB1 { get; set; }

        public SMBSecurityModeEnum SMB1SecurityMode { get; set; }

        public bool SupportSMB2OrSMB3 { get; set; }

        public SMBSecurityModeEnum SMB2SecurityMode { get; set; }

        public bool RemoteSpoolerDetected { get; set; }

        public List<string> IP { get; set; }

        public List<string> FSMO { get; set; }

        public List<string> LDAPSProtocols { get; set; }

        public bool ChannelBindingDisabled { get; set; }

        public bool LdapServerSigningRequirementDisabled { get; set; }

        public DateTime PwdLastSet { get; set; }

        public string RegistrationProblem { get; set; }

        public byte[] LDAPCertificate { get; set; }

        [DefaultValue(null)]
        public List<HealthcheckDomainControllerDelegation> Delegations { get; set; }

        [XmlIgnore]
        [IgnoreDataMember]
        public List<string> msDSRevealedUsers { get; set; }

        [XmlIgnore]
        [IgnoreDataMember]
        public List<string> msDSRevealOnDemandGroup { get; set; }

        [XmlIgnore]
        [IgnoreDataMember]
        public List<string> msDSNeverRevealGroup { get; set; }

        public bool RODC { get; set; }

        public bool SYSVOLOverwrite { get; set; }

        [XmlAttribute]
        [DefaultValue(false)]
        public bool AzureADKerberos { get; set; }

        [XmlAttribute]
        [DefaultValue(false)]
        public bool WebClientEnabled { get; set; }

        [XmlAttribute]
        public DateTime AdminLocalLogin { get; set; }

        public List<HealthcheckDCRPCInterface> RPCInterfacesOpen { get; set; }

    }

    [XmlType("delegation")]
    public class HealthcheckDomainControllerDelegation
    {
        [XmlAttribute]
        public string Delegate { get; set; }
        [XmlAttribute]
        public string DelegateSid { get; set; }
        [XmlAttribute]
        public string DelegationType { get; set; }
    }

    [DebuggerDisplay("{DCName}")]
    public class HealthcheckExchangeServer
    {
        public string Name { get; set; }

        public DateTime CreationDate { get; set; }

        public DateTime ChangedDate { get; set; }



        public int ServerRoles { get; set; }

        public string[] ComponentStates { get; set; }

        public string InternetWebProxy { get; set; }

        public string SerialNumber { get; set; }
    }

    [DebuggerDisplay("{SiteName}")]
    public class HealthcheckSite
    {
        public string SiteName { get; set; }
        public string Description { get; set; }
        public string Location { get; set; }
        public List<string> Networks { get; set; }
    }

    public class HealthcheckDnsZones
    {
        public string name { get; set; }
        public bool InsecureUpdate { get; set; }

        public bool ZoneTransfert { get; set; }

        [XmlAttribute]
        [DefaultValue(false)]
        public bool AUCreateChild { get; set; }

        public string DistinguishedName { get; set; }

        public string Partition { get; set; }
    }

    [XmlType("Dist")]
    public class HealthcheckPwdDistributionData
    {
        [XmlAttribute]
        public int HigherBound { get; set; }
        [XmlAttribute]
        public int Value { get; set; }
    }

    public class HealthcheckSchemaClassVulnerable
    {
        [XmlAttribute]
        public string Class { get; set; }
        [XmlAttribute]
        public string Vulnerability { get; set; }
    }

    [DebuggerDisplay("{Domain}")]
    public class HealthcheckData : IRiskEvaluation, IPingCastleReport
    {
        public string EngineVersion { get; set; }
        public DateTime GenerationDate { get; set; }

        public bool IsPrivilegedMode { get; set; }

        private static bool UseDateInFileNameValue = false;

        public static void UseDateInFileName()
        {
            UseDateInFileNameValue = true;
        }


        public string GetHumanReadableFileName()
        {
            return GetHumanReadableFileName(DomainFQDN, GenerationDate);
        }

        public string GetMachineReadableFileName()
        {
            return GetMachineReadableFileName(DomainFQDN, GenerationDate);
        }

        public static string GetHumanReadableFileName(string DomainFQDN, DateTime GenerationDate)
        {
            return "ad_hc_" + DomainFQDN + (UseDateInFileNameValue ? "_" + GenerationDate.ToString("yyyyMMddTHHmmss") : null) + ".html";
        }

        public static string GetMachineReadableFileName(string DomainFQDN, DateTime GenerationDate)
        {
            return "ad_hc_" + DomainFQDN + (UseDateInFileNameValue ? "_" + GenerationDate.ToString("yyyyMMddTHHmmss") : null) + ".xml";
        }

        public void SetExportLevel(PingCastleReportDataExportLevel level)
        {
            Level = level;
        }

        public void SetIntegrity()
        {
            Trace.WriteLine("SetIntegrity called");
            IntegrityRules = ComputeIntegrity();
            IntegrityVerified = true;
        }

        public void CheckIntegrity()
        {
            if (new Version(EngineVersion.Split(' ')[0]) > new Version(3, 0))
            {
                if (string.IsNullOrEmpty(IntegrityRules))
                    Trace.WriteLine("IntegrityRules empty");
                var expected = ComputeIntegrity();
                IntegrityVerified = IntegrityRules == expected;
                if (!IntegrityVerified)
                {
                    Trace.WriteLine("Integrity not verified");
                    Trace.WriteLine("expected: " + expected);
                    Trace.WriteLine("IntegrityRules: " + IntegrityRules);
                }
            }
            else
            {
                IntegrityVerified = true;
            }
        }

        public string ComputeIntegrity()
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
                Trace.WriteLine("Integrity string: " + s);
                var h = hash.ComputeHash(Encoding.UTF8.GetBytes(s));
                var o = Convert.ToBase64String(h);
                return o;
            }
        }

        // this property is used to limit the serialization of some properties
        private PingCastleReportDataExportLevel _level;
        public PingCastleReportDataExportLevel Level
        {
            get
            {
                return _level;
            }
            set
            {
                _level = value;
                // if the value is changed, propagate it to properties which needs it
                if (UserAccountData != null)
                {
                    UserAccountData.Level = value;
                }
                if (ComputerAccountData != null)
                {
                    ComputerAccountData.Level = value;
                }
                if (PrivilegedGroups != null)
                {
                    foreach (var group in PrivilegedGroups)
                    {
                        group.Level = value;
                    }
                }
                if (RiskRules != null)
                {
                    foreach (var rule in RiskRules)
                    {
                        rule.Level = value;
                    }
                }
                if (ControlPaths != null && ControlPaths.Data != null)
                {
                    foreach (var d in ControlPaths.Data)
                    {
                        d.Level = value;
                    }
                }
            }
        }

        public void InitializeReportingData()
        {
            version = new Version(EngineVersion.Split(' ')[0]);

            applicableRules = new List<RuleBase<HealthcheckData>>();
            foreach (var rule in RuleSet<HealthcheckData>.Rules)
            {
                object[] models = rule.GetType().GetCustomAttributes(typeof(RuleIntroducedInAttribute), true);
                if (models != null && models.Length != 0)
                {
                    RuleIntroducedInAttribute model = (RuleIntroducedInAttribute)models[0];
                    if (model.Version <= version)
                    {
                        applicableRules.Add(rule);
                    }
                }
                else
                {
                    applicableRules.Add(rule);
                }
            }
            if (MaturityLevel == 0)
            {
                MaturityLevel = 5;
                foreach (var rule in RiskRules)
                {
                    var hcrule = RuleSet<HealthcheckData>.GetRuleFromID(rule.RiskId);
                    if (hcrule == null)
                    {
                        continue;
                    }
                    int level = hcrule.MaturityLevel;
                    if (level > 0 && level < MaturityLevel)
                        MaturityLevel = level;
                }
            }
        }
        [IgnoreDataMember]
        [XmlIgnore]
        public Version version { get; set; }

        public int MaturityLevel { get; set; }

        [IgnoreDataMember]
        [XmlIgnore]
        public List<RuleBase<HealthcheckData>> applicableRules { get; set; }

        private Dictionary<string, GPOInfo> _GPOInfoDic;
        [IgnoreDataMember]
        [XmlIgnore]
        public Dictionary<string, GPOInfo> GPOInfoDic
        {
            get
            {
                if (_GPOInfoDic != null)
                    return _GPOInfoDic;
                _GPOInfoDic = new Dictionary<string, GPOInfo>(StringComparer.OrdinalIgnoreCase);
                foreach (var gpo in GPOInfo)
                {
                    if (!_GPOInfoDic.ContainsKey(gpo.GPOId))
                    {
                        _GPOInfoDic.Add(gpo.GPOId, gpo);
                    }
                }
                return _GPOInfoDic;
            }
        }

        [XmlAttribute]
        public string IntegrityRules { get; set; }
        [IgnoreDataMember]
        [XmlIgnore]
        public bool IntegrityVerified { get; set; }

        public string DomainFQDN { get; set; }
        public string NetBIOSName { get; set; }
        public string ForestFQDN { get; set; }

        public DateTime DomainCreation { get; set; }
        public string DomainSid { get; set; }

        public int DomainFunctionalLevel { get; set; }
        public int ForestFunctionalLevel { get; set; }
        public int SchemaVersion { get; set; }
        public int SchemaInternalVersion { get; set; }
        public bool IsRecycleBinEnabled { get; set; }
        public DateTime DCWin2008Install { get; set; }

        public DateTime SchemaLastChanged { get; set; }
        public int NumberOfDC { get; set; }
        public int GlobalScore { get; set; }
        public int StaleObjectsScore { get; set; }
        public int PrivilegiedGroupScore { get; set; }
        public int TrustScore { get; set; }
        public int AnomalyScore { get; set; }

        public DateTime ExchangeInstall { get; set; }
        public int ExchangeSchemaVersion { get; set; }

        public bool ShouldSerializeDefaultOUChanged() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public List<HealthcheckOUChangedData> DefaultOUChanged { get; set; }

        public bool ShouldSerializeTrusts() { return (int)Level <= (int)PingCastleReportDataExportLevel.Light; }
        public List<HealthCheckTrustData> Trusts { get; set; }

        public bool ShouldSerializeReachableDomains() { return (int)Level <= (int)PingCastleReportDataExportLevel.Light; }
        public List<HealthCheckTrustDomainInfoData> ReachableDomains { get; set; }

        public bool ShouldSerializeDomainControllers() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public List<HealthcheckDomainController> DomainControllers { get; set; }

        public List<HealthcheckExchangeServer> ExchangeServers { get; set; }

        public bool ShouldSerializeSites() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public List<HealthcheckSite> Sites { get; set; }

        public bool ShouldSerializelDAPIPDenyList() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public List<string> lDAPIPDenyList { get; set; }

        public bool ShouldSerializePreWindows2000AnonymousAccess() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public bool PreWindows2000AnonymousAccess { get; set; }

        public bool ShouldSerializePreWindows2000NoDefault() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public bool PreWindows2000NoDefault { get; set; }

        public bool ShouldSerializePreWindows2000AuthenticatedUsers() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public bool PreWindows2000AuthenticatedUsers { get; set; }

        public bool ShouldSerializePreWindows2000Members() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public List<string> PreWindows2000Members { get; set; }

        [DefaultValue(null)]
        [XmlAttribute]
        public string DSHeuristics { get; set; }

        [DefaultValue(null)]
        public List<string> DSOtherSettings { get; set; }

        public bool ShouldSerializeUsingNTFRSForSYSVOL() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public bool UsingNTFRSForSYSVOL { get; set; }

        public bool ShouldSerializeRiskRules() { return (int)Level <= (int)PingCastleReportDataExportLevel.Light; }
        public List<HealthcheckRiskRule> RiskRules { get; set; }

        [IgnoreDataMember]
        [XmlIgnore]
        public IList<IRuleScore> AllRiskRules { get { return RiskRules.ConvertAll(x => { return (IRuleScore)x; }); } }

        public bool ShouldSerializeUserAccountData() { return (int)Level <= (int)PingCastleReportDataExportLevel.Light; }
        public HealthcheckAccountData UserAccountData { get; set; }

        public bool ShouldSerializeComputerAccountData() { return (int)Level <= (int)PingCastleReportDataExportLevel.Light; }
        public HealthcheckAccountData ComputerAccountData { get; set; }

        public bool ShouldSerializeOperatingSystem() { return (int)Level <= (int)PingCastleReportDataExportLevel.Light; }
        public List<HealthcheckOSData> OperatingSystem { get; set; }

        public bool ShouldSerializeOperatingSystemVersion() { return (int)Level <= (int)PingCastleReportDataExportLevel.Light; }
        public List<HealthcheckOSVersionData> OperatingSystemVersion { get; set; }

        // DO NOT USE - former data
        public bool ShouldSerializeOperatingSystemDC() { return (int)Level <= (int)PingCastleReportDataExportLevel.Light; }
        public List<HealthcheckOSData> OperatingSystemDC { get; set; }

        public bool ShouldSerializeListComputerPwdNotChanged() { return (int)Level <= (int)PingCastleReportDataExportLevel.Full; }
        public List<HealthcheckAccountDetailData> ListComputerPwdNotChanged { get; set; }

        public bool ShouldSerializeListClusterPwdNotChanged() { return (int)Level <= (int)PingCastleReportDataExportLevel.Full; }
        public List<HealthcheckAccountDetailData> ListClusterPwdNotChanged { get; set; }

        public bool ShouldSerializeGPOInfo() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public List<GPOInfo> GPOInfo { get; set; }

        public bool ShouldSerializeLoginScript() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public List<HealthcheckLoginScriptData> LoginScript { get; set; }

        public bool ShouldSerializeLastADBackup() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public DateTime LastADBackup { get; set; }

        public bool ShouldSerializeLAPSInstalled() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public DateTime LAPSInstalled { get; set; }
        public bool ShouldSerializeNewLAPSInstalled() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public DateTime NewLAPSInstalled { get; set; }

        public bool ShouldSerializeSCCMInstalled() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public DateTime SCCMInstalled { get; set; }

        public bool ShouldSerializeListLAPSJoinedComputersToReview() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public List<HealthcheckAccountDetailData> ListLAPSJoinedComputersToReview { get; set; }

        public bool ShouldSerializeKrbtgtLastChangeDate() { return (int)Level <= (int)PingCastleReportDataExportLevel.Light; }
        public DateTime KrbtgtLastChangeDate { get; set; }

        public bool ShouldSerializeKrbtgtLastVersion() { return (int)Level <= (int)PingCastleReportDataExportLevel.Light; }
        public int KrbtgtLastVersion { get; set; }

        public bool ShouldSerializeExchangePrivEscVulnerable() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public bool ExchangePrivEscVulnerable { get; set; }

        public bool ShouldSerializeAdminLastLoginDate() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public DateTime AdminLastLoginDate { get; set; }

        public bool ShouldSerializeAdminAccountName() { return (int)Level <= (int)PingCastleReportDataExportLevel.Full; }
        public string AdminAccountName { get; set; }

        public bool GuestEnabled { get; set; }

        public bool ShouldSerializeGPPPassword() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public List<GPPPassword> GPPPassword { get; set; }

        public bool ShouldSerializeGPPFileDeployed() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public List<GPPFileDeployed> GPPFileDeployed { get; set; }

        public bool ShouldSerializeGPPFirewallRules() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public List<GPPFireWallRule> GPPFirewallRules { get; set; }

        public bool ShouldSerializeGPPTerminalServiceConfigs() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public List<GPPTerminalServiceConfig> GPPTerminalServiceConfigs {get;set;}

        public bool ShouldSerializeGPPRightAssignment() { return (int)Level <= (int)PingCastleReportDataExportLevel.Full; }
        public List<GPPRightAssignment> GPPRightAssignment { get; set; }

        public bool ShouldSerializeGPPLoginAllowedOrDeny() { return (int)Level <= (int)PingCastleReportDataExportLevel.Full; }
        public List<GPPRightAssignment> GPPLoginAllowedOrDeny { get; set; }

        public bool ShouldSerializeGPOAuditSimple() { return (int)Level <= (int)PingCastleReportDataExportLevel.Light; }
        public List<GPOAuditSimpleData> GPOAuditSimple { get; set; }

        public bool ShouldSerializeGPOAuditAdvanced() { return (int)Level <= (int)PingCastleReportDataExportLevel.Light; }
        public List<GPOAuditAdvancedData> GPOAuditAdvanced { get; set; }

        public List<HealthcheckWSUSData> GPOWSUS { get; set; }

        public bool ShouldSerializeGPPPasswordPolicy() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public List<GPPSecurityPolicy> GPPPasswordPolicy { get; set; }

        public bool ShouldSerializeGPOLsaPolicy() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public List<GPPSecurityPolicy> GPOLsaPolicy { get; set; }

        public bool ShouldSerializeGPOFolderOptions() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public List<GPPFolderOption> GPOFolderOptions { get; set; }

        public bool ShouldSerializeGPODefenderASR() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public List<HealthcheckDefenderASRData> GPODefenderASR { get; set; }

        public bool ShouldSerializeGPOScreenSaverPolicy() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public List<GPPSecurityPolicy> GPOScreenSaverPolicy { get; set; }

        public bool ShouldSerializeGPOEventForwarding() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public List<GPOEventForwardingInfo> GPOEventForwarding { get; set; }

        public bool ShouldSerializeGPODelegation() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public List<GPODelegationData> GPODelegation { get; set; }

        public bool ShouldSerializeGPOLocalMembership() { return (int)Level <= (int)PingCastleReportDataExportLevel.Full; }
        public List<GPOMembership> GPOLocalMembership { get; set; }

        public bool ShouldSerializeGPOHardenedPath() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public List<GPPHardenedPath> GPOHardenedPath { get; set; }

        public bool ShouldSerializeTrustedCertificates() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public List<HealthcheckCertificateData> TrustedCertificates { get; set; }

        public bool ShouldSerializeCertificateTemplates() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }

        public List<HealthCheckCertificateAuthorityData> CertificateAuthorities { get; set; }   

        public List<HealthCheckCertificateTemplate> CertificateTemplates { get; set; }

        public bool ShouldSerializeCertificateEnrollments() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public List<HealthCheckCertificateEnrollment> CertificateEnrollments { get; set; }

        public bool ShouldSerializeSCCMServers() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public List<HealthCheckSCCMServer> SCCMServers { get; set; }

        public bool ShouldSerializePrivilegedGroups() { return (int)Level <= (int)PingCastleReportDataExportLevel.Light; }
        public List<HealthCheckGroupData> PrivilegedGroups { get; set; }

        public bool ShouldSerializeAllPrivilegedMembers() { return (int)Level <= (int)PingCastleReportDataExportLevel.Full; }
        public List<HealthCheckGroupMemberData> AllPrivilegedMembers { get; set; }

        public bool ShouldSerializeProtectedUsersNotPrivileged() { return (int)Level <= (int)PingCastleReportDataExportLevel.Full; }
        public HealthCheckGroupData ProtectedUsersNotPrivileged { get; set; }

        public bool ShouldSerializeAdminSDHolderNotOKCount() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public int AdminSDHolderNotOKCount { get; set; }

        public bool ShouldSerializeAdminSDHolderNotOK() { return (int)Level <= (int)PingCastleReportDataExportLevel.Full; }
        public List<HealthcheckAccountDetailData> AdminSDHolderNotOK { get; set; }

        public bool ShouldSerializeUnixPasswordUsersCount() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public int UnixPasswordUsersCount { get; set; }

        public bool ShouldSerializeUnixPasswordUsers() { return (int)Level <= (int)PingCastleReportDataExportLevel.Full; }
        public List<HealthcheckAccountDetailData> UnixPasswordUsers { get; set; }

        public bool ShouldSerializeSmartCardNotOKCount() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public int SmartCardNotOKCount { get; set; }

        public bool ShouldSerializeSmartCardNotOK() { return (int)Level <= (int)PingCastleReportDataExportLevel.Full; }
        public List<HealthcheckAccountDetailData> SmartCardNotOK { get; set; }

        public bool ShouldSerializeRODCKrbtgtOrphans() { return (int)Level <= (int)PingCastleReportDataExportLevel.Full; }
        public List<HealthcheckAccountDetailData> RODCKrbtgtOrphans { get; set; }

        public bool ShouldSerializeDelegations() { return (int)Level <= (int)PingCastleReportDataExportLevel.Full; }
        public List<HealthcheckDelegationData> Delegations { get; set; }

        public bool ShouldSerializeUnprotectedOU() { return (int)Level <= (int)PingCastleReportDataExportLevel.Full; }
        public List<string> UnprotectedOU { get; set; }

        public bool ShouldSerializeGPOLoginScript() { return (int)Level <= (int)PingCastleReportDataExportLevel.Full; }
        public List<HealthcheckGPOLoginScriptData> GPOLoginScript { get; set; }

        public bool ShouldSerializeDomainControllerWithNullSessionCount() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public int DomainControllerWithNullSessionCount { get; set; }

        public bool ShouldSerializeSIDHistoryAuditingGroupPresent() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public bool SIDHistoryAuditingGroupPresent { get; set; }

        public bool ShouldSerializeMachineAccountQuota() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public int MachineAccountQuota { get; set; }

        public bool ShouldSerializeExpirePasswordsOnSmartCardOnlyAccounts() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        [DefaultValue(false)]
        [XmlAttribute]
        public bool ExpirePasswordsOnSmartCardOnlyAccounts { get; set; }

        public bool ShouldSerializeListHoneyPot() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public List<HealthcheckAccountDetailData> ListHoneyPot { get; set; }

        public bool ShouldSerializeAllowedRODCPasswordReplicationGroup() { return false; }
        public List<string> AllowedRODCPasswordReplicationGroup { get; set; }

        public bool ShouldSerializeDeniedRODCPasswordReplicationGroup() { return false; }
        public List<string> DeniedRODCPasswordReplicationGroup { get; set; }

        public bool ShouldSerializeDnsZones() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public List<HealthcheckDnsZones> DnsZones { get; set; }

        public bool ShouldSerializePasswordDistribution() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public List<HealthcheckPwdDistributionData> PasswordDistribution { get; set; }

        public bool ShouldSerializeLapsDistribution() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public List<HealthcheckPwdDistributionData> LapsDistribution { get; set; }

        public bool ShouldSerializeLapsNewDistribution() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public List<HealthcheckPwdDistributionData> LapsNewDistribution { get; set; }

        public bool ShouldSerializeAzureADSSOLastPwdChange() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public DateTime AzureADSSOLastPwdChange { get; set; }

        public bool ShouldSerializeAzureADSSOVersion() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public int AzureADSSOVersion { get; set; }

        public bool ShouldSerializeAzureADSSOEncryptionType() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public int AzureADSSOEncryptionType { get; set; }

        public bool ShouldSerializePrivilegedDistributionLastLogon() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public List<HealthcheckPwdDistributionData> PrivilegedDistributionLastLogon { get; set; }

        public bool ShouldSerializePrivilegedDistributionPwdLastSet() { return (int)Level <= (int)PingCastleReportDataExportLevel.Normal; }
        public List<HealthcheckPwdDistributionData> PrivilegedDistributionPwdLastSet { get; set; }

        public List<HealthcheckSchemaClassVulnerable> SchemaClassVulnerable { get; set; }

        public List<HealthCheckServicePoint> ServicePoints { get; set; }
        public List<HealthCheckMSOL> AzureADConnect { get; set; }

        public bool JavaClassFound { get; set; }
        public List<HealthcheckAccountDetailData> JavaClassFoundDetail { get; set; }

        public string AzureADName { get; set; }
        public string AzureADId { get; set; }
        public string AzureADKerberosSid { get; set; }

        [DefaultValue(0)]
        [XmlAttribute]
        public uint WinTrustLevel { get; set; }

        public List<HealthCheckDisplaySpecifier> DisplaySpecifier { get; set; }

        private DomainKey _domain;
        [IgnoreDataMember]
        [XmlIgnore]
        public DomainKey Domain
        {
            get
            {
                if (_domain == null)
                {
                    _domain = DomainKey.Create(DomainFQDN, DomainSid, NetBIOSName);
                }
                return _domain;
            }
        }

        private DomainKey _forest;

        [IgnoreDataMember]
        [XmlIgnore]
        public DomainKey Forest
        {
            get
            {
                if (_forest == null)
                {
                    if (String.Equals(ForestFQDN, DomainFQDN, StringComparison.InvariantCultureIgnoreCase))
                    {
                        _forest = Domain;
                    }
                    else
                    {
                        string sid = null;
                        string netbiosname = null;
                        if (Trusts != null)
                        {
                            foreach (var trust in Trusts)
                            {
                                if (String.Equals(trust.TrustPartner, ForestFQDN, StringComparison.InvariantCultureIgnoreCase))
                                {
                                    if (!String.IsNullOrEmpty(trust.SID))
                                    {
                                        sid = trust.SID;
                                        netbiosname = trust.NetBiosName;
                                    }
                                    break;
                                }
                            }
                        }
                        _forest = DomainKey.Create(ForestFQDN, sid, netbiosname);
                    }
                }
                return _forest;
            }
        }

        [IgnoreDataMember]
        [XmlIgnore]
        public IList<DomainKey> DomainKnown
        {
            get
            {
                var output = new List<DomainKey>();
                output.Add(Domain);
                if (Forest != null)
                {
                    if (Domain.DomainName != Forest.DomainName)
                        output.Add(Forest);
                }
                if (Trusts != null)
                {
                    foreach (var t in Trusts)
                    {
                        output.Add(t.Domain);
                        if (t.KnownDomains != null)
                        {
                            foreach (var d in t.KnownDomains)
                            {
                                output.Add(d.Domain);
                                if (d.Forest != null)
                                    output.Add(d.Forest);
                            }
                        }
                    }
                }
                if (ReachableDomains != null)
                {
                    foreach (var d in ReachableDomains)
                    {
                        output.Add(d.Domain);
                        if (d.Forest != null)
                            output.Add(d.Forest);
                    }
                }
                return output;
            }
        }

        public CompromiseGraphData ControlPaths { get; set; }

        public bool HasKdsRootKey { get; set; }
    }
}
