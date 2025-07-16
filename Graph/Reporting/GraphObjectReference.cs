using PingCastle.ADWS;
using PingCastle.Data;
using System.Collections.Generic;

namespace PingCastle.Graph.Reporting
{
    public class GraphSingleObject
    {
        public GraphSingleObject(string name, string description, CompromiseGraphDataObjectRisk risk = CompromiseGraphDataObjectRisk.Other)
        {
            Name = name;
            Description = description;
            Risk = risk;
        }

        public string Name { get; set; }
        public string Description { get; set; }
        public CompromiseGraphDataObjectRisk Risk { get; set; }
    }

    public class GraphObjectReference
    {
        public const string DomainAdministrators = "Domain Administrators";
        public const string Administrators = "Administrators";
        public const string AccountOperators = "Account Operators";
        public const string ServerOperators = "Server Operators";
        public const string PrintOperators = "Print Operators";
        public const string BackupOperators = "Backup Operators";
        public const string CertificateOperators = "Certificate Operators";
        public const string Replicator = "Replicator";
        public const string Administrator = "Administrator";
        public const string CertificatePublishers = "Certificate Publishers";
        public const string SchemaAdministrators = "Schema Administrators";
        public const string EnterpriseAdministrators = "Enterprise Administrators";
        public const string KeyAdministrators = "Key Administrators";
        public const string EnterpriseKeyAdministrators = "Enterprise Key Administrators";
        public const string DnsAdministrators = "Dns Admins";
        public const string DeniedRODCPasswordReplicationGroup = "Denied RODC Password Replication Group";
        public const string Everyone = "Everyone";
        public const string Anonymous = "Anonymous";
        public const string AuthenticatedUsers = "Authenticated Users";
        public const string Users = "Users";
        public const string DomainUsers = "Domain Users";
        public const string DomainComputers = "Domain Computers";

        public const string GroupPolicyCreatorOwners = "Group Policy Creator Owners";
        public const string ExchangeDomainServers = "Exchange Domain Servers";
        public const string ExchangeEnterpriseServers = "Exchange Enterprise Servers";
        public const string ExchangeAdmins = "Exchange Admins";
        public const string OrganizationManagement = "Organization Management";
        public const string ExchangeWindowsPermissions = "Exchange Windows Permissions";

        public Dictionary<CompromiseGraphDataTypology, List<GraphSingleObject>> Objects { get; set; }
        public List<string> TechnicalObjects { get; set; }

        public GraphObjectReference(ADDomainInfo data)
        {
            Objects = new Dictionary<CompromiseGraphDataTypology, List<GraphSingleObject>>
            {
                {
                    CompromiseGraphDataTypology.PrivilegedAccount, new List<GraphSingleObject>
                    {
                        new GraphSingleObject("S-1-5-32-544", Administrators, CompromiseGraphDataObjectRisk.Critical),
                        new GraphSingleObject("S-1-5-32-548", AccountOperators, CompromiseGraphDataObjectRisk.High),
                        new GraphSingleObject("S-1-5-32-549", ServerOperators, CompromiseGraphDataObjectRisk.High),
                        new GraphSingleObject("S-1-5-32-550", PrintOperators, CompromiseGraphDataObjectRisk.Medium),
                        new GraphSingleObject("S-1-5-32-551", BackupOperators, CompromiseGraphDataObjectRisk.High),
                        new GraphSingleObject("S-1-5-32-569", CertificateOperators, CompromiseGraphDataObjectRisk.Medium),
                        new GraphSingleObject("S-1-5-32-552", Replicator, CompromiseGraphDataObjectRisk.Medium),
                        new GraphSingleObject(data.DomainSid.Value + "-500", Administrator, CompromiseGraphDataObjectRisk.Critical),
                        new GraphSingleObject(data.DomainSid.Value + "-512", DomainAdministrators, CompromiseGraphDataObjectRisk.Critical),
                        new GraphSingleObject(data.DomainSid.Value + "-517", CertificatePublishers), 
                        new GraphSingleObject(data.DomainSid.Value + "-518", SchemaAdministrators, CompromiseGraphDataObjectRisk.Critical),
                        new GraphSingleObject(data.DomainSid.Value + "-519", EnterpriseAdministrators, CompromiseGraphDataObjectRisk.Critical),
                        new GraphSingleObject(data.DomainSid.Value + "-526", KeyAdministrators, CompromiseGraphDataObjectRisk.Medium),
                        new GraphSingleObject(data.DomainSid.Value + "-527", EnterpriseKeyAdministrators, CompromiseGraphDataObjectRisk.Medium),
                    }
                },
                {
                    CompromiseGraphDataTypology.Infrastructure, new List<GraphSingleObject>
                    {
                        new GraphSingleObject(data.DomainSid.Value, "Domain Root", CompromiseGraphDataObjectRisk.Medium),
                        new GraphSingleObject(data.DomainSid.Value + "-498", "Enterprise Read Only Domain Controllers"),
                        new GraphSingleObject(data.DomainSid.Value + "-502", "Krbtgt account", CompromiseGraphDataObjectRisk.Medium),
                        new GraphSingleObject(data.DomainSid.Value + "-516", "Domain Controllers", CompromiseGraphDataObjectRisk.Critical),
                        new GraphSingleObject(data.DomainSid.Value + "-520", "Group Policy Creator Owners", CompromiseGraphDataObjectRisk.Medium),
                        new GraphSingleObject(data.DomainSid.Value + "-521", "Read Only Domain Controllers", CompromiseGraphDataObjectRisk.Medium),
                        new GraphSingleObject("CN=Builtin," + data.DefaultNamingContext, "Builtin OU", CompromiseGraphDataObjectRisk.Medium),
                        new GraphSingleObject("CN=Users," + data.DefaultNamingContext, "Users container", CompromiseGraphDataObjectRisk.Medium),
                        new GraphSingleObject("CN=Computers," + data.DefaultNamingContext, "Computers container", CompromiseGraphDataObjectRisk.Medium),
                        new GraphSingleObject("CN=NTAuthCertificates,CN=Public Key Services,CN=Services," + data.ConfigurationNamingContext, "Certificate store", CompromiseGraphDataObjectRisk.Medium),
                        new GraphSingleObject("CN=AdminSDHolder,CN=System," + data.DefaultNamingContext, "AdminSDHolder container", CompromiseGraphDataObjectRisk.Critical),
                    }
                },
                {
                    CompromiseGraphDataTypology.UserDefined, new List<GraphSingleObject>()
                }
            };

            foreach (var typology in Objects.Keys)
            {
                Objects[typology].Sort((a, b)
                    => string.CompareOrdinal(a.Description, b.Description));
            }

            TechnicalObjects = new List<string> { data.DomainSid.Value + "-525" };
        }
    }
}