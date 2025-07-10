using PingCastle.ADWS;
using PingCastle.Data;
using PingCastle.Graph.Reporting;
using PingCastle.Rules;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection;

namespace PingCastle.Healthcheck
{

    public class FakeHealthCheckDataGeneratorModel
    {
        public int NumberOfDomains;
        public int TrustRatioInPercent;
    }

    public enum DomainSizeModel
    {
        Large,
        Medium,
        Small,
        VerySmall,
    }
    public class FakeHealthCheckDataGeneratorDomainModel
    {
        public HealthcheckData Forest;
        public DomainSizeModel Size;
    }

    public class FakeHealthCheckDataGenerator
    {
        static List<string> TopEnd = new List<string>()
        {
            "com",
            "local",
            "org",
            "net",
        };

        static List<string> TopNouns = new List<string>() {
            "time",
            "person",
            "year",
            "way",
            "day",
            "thing",
            "man",
            "world",
            "life",
            "hand",
            "part",
            "child",
            "eye",
            "woman",
            "place",
            "work",
            "week",
            "case",
            "point",
            "government",
            "company",
            "number",
            "group",
            "problem",
            "fact",
            "insurance",
            "airline",
            "bank",
            "coffee",
            "construction",
            "energy",
            "military",
        };

        static List<string> TopAdjectives = new List<string>() {
            "good",
            "new",
            "first",
            "last",
            "long",
            "great",
            "little",
            "own",
            "other",
            "old",
            "right",
            "big",
            "high",
            "different",
            "small",
            "large",
            "next",
            "early",
            "young",
            "important",
            "few",
            "public",
            "bad",
            "same",
            "able",
        };

        static List<string> LocalNames = new List<string>()
        {
            "hq",
            "corp",
            "france",
            "uk",
            "germany",
            "dmz",
            "servers",
            "merger",
            "home",
            "bastion",
            "norway",
            "canada",
            "us",
            "china",
            "india",
            "brasil",
            "russia",
            "mexico",
            "paris",
            "berlin",
            "london",
            "newyork",
            "incentivize",
            "core",
            "admin",
            "schedule",
            "process",
            "documents",
            "files",
            "mail",
        };

        static Random rnd = new Random();
        static string FQDNGenerator()
        {
            return TopAdjectives[rnd.Next(TopAdjectives.Count)] + TopNouns[rnd.Next(TopNouns.Count)] + "." + TopEnd[rnd.Next(TopEnd.Count)];
        }

        static string ChildGenerator()
        {
            return LocalNames[rnd.Next(LocalNames.Count)] + rnd.Next(100);
        }

        public PingCastleReportCollection<HealthcheckData> GenerateData()
        {
            return GenerateData(new FakeHealthCheckDataGeneratorModel()
            {
                NumberOfDomains = 50,
                TrustRatioInPercent = 40,
            });
        }
        public PingCastleReportCollection<HealthcheckData> GenerateData(FakeHealthCheckDataGeneratorModel model)
        {
            var output = new PingCastleReportCollection<HealthcheckData>();

            var num = 0;
            while (num < model.NumberOfDomains - 1)
            {
                int value = rnd.Next(100);
                if (value < 20 && model.NumberOfDomains - num > 6)
                {
                    foreach (var d in GenerateForest(model.NumberOfDomains - num))
                    {
                        output.Add(d);
                        num++;
                    }
                }
                if (value < 60)
                {
                    output.Add(GenerateSingleReport(new FakeHealthCheckDataGeneratorDomainModel() { Size = DomainSizeModel.Small }));
                    num++;
                }
                else if (value < 80)
                {
                    output.Add(GenerateSingleReport(new FakeHealthCheckDataGeneratorDomainModel() { Size = DomainSizeModel.Medium }));
                    num++;
                }
                else
                {
                    output.Add(GenerateSingleReport(new FakeHealthCheckDataGeneratorDomainModel() { Size = DomainSizeModel.Large }));
                    num++;
                }
            }
            int numberOfTrust = model.NumberOfDomains * model.TrustRatioInPercent / 100;
            for (int i = 0; i < numberOfTrust; i++)
            {
                //take 2 random domains
                int a = rnd.Next(output.Count);
                int b = rnd.Next(output.Count);
                while (a == b)
                {
                    b = rnd.Next(output.Count);
                }
                var source = GetItem(output, a);
                var destination = GetItem(output, b);

                //bool forestTrust = false;

                bool uniDirectional = false;

                bool sidfiltering = false;

                DateTime trustCreation = DateBetween2Dates(new DateTime(Math.Max(source.DomainCreation.Ticks, destination.DomainCreation.Ticks)), DateTime.Now);

                var trust = new HealthCheckTrustData();
                trust.CreationDate = trustCreation;
                trust.IsActive = true;
                trust.NetBiosName = destination.NetBIOSName;
                trust.SID = destination.DomainSid;
                trust.TrustDirection = (uniDirectional ? 1 : 3);
                trust.TrustAttributes = (sidfiltering ? 4 : 0);
                trust.TrustType = 2;
                trust.TrustPartner = destination.DomainFQDN;
                trust.SID = destination.DomainSid;
                trust.KnownDomains = new List<HealthCheckTrustDomainInfoData>();
                source.Trusts.Add(trust);

                trust = new HealthCheckTrustData();
                trust.CreationDate = trustCreation;
                trust.IsActive = true;
                trust.NetBiosName = source.NetBIOSName;
                trust.SID = source.DomainSid;
                trust.TrustDirection = (uniDirectional ? 2 : 3);
                trust.TrustAttributes = (sidfiltering ? 4 : 0);
                trust.TrustType = 2;
                trust.TrustPartner = source.DomainFQDN;
                trust.SID = source.DomainSid;
                trust.KnownDomains = new List<HealthCheckTrustDomainInfoData>();
                destination.Trusts.Add(trust);
            }
            return output;
        }

        HealthcheckData GetItem(PingCastleReportCollection<HealthcheckData> reports, int rank)
        {
            var e = reports.GetEnumerator();
            e.MoveNext();
            for (int i = 0; i < rank; i++)
            {
                e.MoveNext();
            }
            return e.Current;
        }

        public PingCastleReportCollection<HealthcheckData> GenerateForest(int maxDomain = 15)
        {
            int numberDomains = rnd.Next(5, maxDomain > 15 ? 15 : maxDomain);
            var children = new PingCastleReportCollection<HealthcheckData>();
            // head of forest
            var root = GenerateSingleReport(new FakeHealthCheckDataGeneratorDomainModel() { Size = DomainSizeModel.VerySmall });
            for (int i = 0; i < numberDomains; i++)
            {
                var child = GenerateSingleReport(new FakeHealthCheckDataGeneratorDomainModel() { Size = DomainSizeModel.Medium, Forest = root });
                children.Add(child);
            }
            foreach (var child in children)
            {
                // root trust
                var trust = new HealthCheckTrustData();
                trust.CreationDate = child.DomainCreation;
                trust.IsActive = true;
                trust.NetBiosName = child.NetBIOSName;
                trust.SID = child.DomainSid;
                trust.TrustDirection = 3;
                trust.TrustAttributes = 32;
                trust.TrustType = 2;
                trust.TrustPartner = child.DomainFQDN;
                trust.SID = child.DomainSid;
                trust.KnownDomains = new List<HealthCheckTrustDomainInfoData>();
                root.Trusts.Add(trust);

                // child trust
                trust = new HealthCheckTrustData();
                trust.CreationDate = child.DomainCreation;
                trust.IsActive = true;
                trust.NetBiosName = root.NetBIOSName;
                trust.SID = child.DomainSid;
                trust.TrustDirection = 3;
                trust.TrustAttributes = 32;
                trust.TrustType = 2;
                trust.TrustPartner = root.DomainFQDN;
                trust.SID = root.DomainSid;
                trust.KnownDomains = new List<HealthCheckTrustDomainInfoData>();
                child.Trusts.Add(trust);

                foreach (var child2 in children)
                {
                    if (child2.DomainSid == child.DomainSid)
                        continue;
                    var kdomain = new HealthCheckTrustDomainInfoData();
                    kdomain.CreationDate = child2.DomainCreation;
                    kdomain.DnsName = child2.DomainFQDN;
                    kdomain.ForestName = child2.ForestFQDN;
                    kdomain.ForestNetbios = root.NetBIOSName;
                    kdomain.ForestSid = root.DomainSid;
                    kdomain.NetbiosName = child2.NetBIOSName;
                    kdomain.Sid = child2.DomainSid;
                    trust.KnownDomains.Add(kdomain);
                }
            }
            // output all domains
            children.Add(root);
            return children;
        }

        public HealthcheckData GenerateSingleReport(FakeHealthCheckDataGeneratorDomainModel model)
        {
            var healthcheckData = new HealthcheckData();

            Trace.WriteLine("Gathering general data");
            GenerateGeneralData(model, healthcheckData);

            Trace.WriteLine("Gathering user data");
            GenerateUserData(model, healthcheckData);

            Trace.WriteLine("Gathering computer data");
            GenerateComputerData(model, healthcheckData);
            Trace.WriteLine("Gathering trust data");
            GenerateTrust(model, healthcheckData);
            Trace.WriteLine("Gathering privileged group and permissions data");
            GeneratePrivilegedData(model, healthcheckData);
            Trace.WriteLine("Gathering delegation data");
            GenerateDelegation(model, healthcheckData);
            Trace.WriteLine("Gathering gpo data");
            GenerateGPOData(model, healthcheckData);
            Trace.WriteLine("Gathering anomaly data");
            GenerateAnomalyData(model, healthcheckData);
            Trace.WriteLine("Gathering domain controller data");
            Trace.WriteLine("Gathering network data");
            GenerateNetworkData(model, healthcheckData);
            Trace.WriteLine("Gathering remaining data");
            GenerateRemainingData(model, healthcheckData);
            Trace.WriteLine("Computing risks");
            var rules = new RuleSet<HealthcheckData>();
            healthcheckData.RiskRules = new List<HealthcheckRiskRule>();
            foreach (var rule in rules.ComputeRiskRules(healthcheckData))
            {
                HealthcheckRiskRule risk = new HealthcheckRiskRule();
                risk.Points = rule.Points;
                risk.Category = rule.Category;
                risk.Model = rule.Model;
                risk.RiskId = rule.RiskId;
                risk.Rationale = rule.Rationale;
                risk.Details = rule.Details;
                risk.ExtraDetails = rule.ExtraDetails;
                healthcheckData.RiskRules.Add(risk);
            }
            Trace.WriteLine("Done");
            return healthcheckData;
        }

        private void GenerateRemainingData(FakeHealthCheckDataGeneratorDomainModel model, HealthcheckData healthcheckData)
        {
            healthcheckData.AllowedRODCPasswordReplicationGroup = new List<string>();
            healthcheckData.DeniedRODCPasswordReplicationGroup = new List<string>();
            healthcheckData.PrivilegedDistributionLastLogon = new List<HealthcheckPwdDistributionData>();
            healthcheckData.PrivilegedDistributionPwdLastSet = new List<HealthcheckPwdDistributionData>();
        }

        private void GenerateTrust(FakeHealthCheckDataGeneratorDomainModel model, HealthcheckData healthcheckData)
        {
            healthcheckData.Trusts = new List<HealthCheckTrustData>();
        }

        private void GenerateNetworkData(FakeHealthCheckDataGeneratorDomainModel model, HealthcheckData healthcheckData)
        {
            healthcheckData.Sites = new List<HealthcheckSite>();
        }

        private void GeneratePrivilegedData(FakeHealthCheckDataGeneratorDomainModel model, HealthcheckData healthcheckData)
        {
            healthcheckData.Delegations = new List<HealthcheckDelegationData>();
            healthcheckData.ControlPaths = new CompromiseGraphData();
            healthcheckData.ControlPaths.Data = new List<SingleCompromiseGraphData>();
            healthcheckData.PrivilegedGroups = new List<HealthCheckGroupData>();
            healthcheckData.AllPrivilegedMembers = new List<HealthCheckGroupMemberData>();
        }

        private void GenerateDelegation(FakeHealthCheckDataGeneratorDomainModel model, HealthcheckData healthcheckData)
        {
            healthcheckData.Delegations = new List<HealthcheckDelegationData>();
        }

        private void GenerateAnomalyData(FakeHealthCheckDataGeneratorDomainModel model, HealthcheckData healthcheckData)
        {
            healthcheckData.SmartCardNotOK = new List<HealthcheckAccountDetailData>();
        }

        private void GenerateGPOData(FakeHealthCheckDataGeneratorDomainModel model, HealthcheckData healthcheckData)
        {
            healthcheckData.GPPPassword = new List<GPPPassword>();
            healthcheckData.GPPRightAssignment = new List<GPPRightAssignment>();
            healthcheckData.GPPLoginAllowedOrDeny = new List<GPPRightAssignment>();
            healthcheckData.GPPPasswordPolicy = new List<GPPSecurityPolicy>();
            healthcheckData.GPOLsaPolicy = new List<GPPSecurityPolicy>();
            healthcheckData.GPOScreenSaverPolicy = new List<GPPSecurityPolicy>();
            healthcheckData.TrustedCertificates = new List<HealthcheckCertificateData>();
            healthcheckData.GPOLoginScript = new List<HealthcheckGPOLoginScriptData>();
            healthcheckData.GPOLocalMembership = new List<GPOMembership>();
            healthcheckData.GPOEventForwarding = new List<GPOEventForwardingInfo>();
            healthcheckData.GPODelegation = new List<GPODelegationData>();
            healthcheckData.GPPFileDeployed = new List<GPPFileDeployed>();
            healthcheckData.GPOAuditSimple = new List<GPOAuditSimpleData>();
            healthcheckData.GPOAuditAdvanced = new List<GPOAuditAdvancedData>();
            healthcheckData.GPOHardenedPath = new List<GPPHardenedPath>();
            healthcheckData.GPOWSUS = new List<HealthcheckWSUSData>();
        }

        class MockupADItem : ADItem
        {

        }

        private void GenerateUserData(FakeHealthCheckDataGeneratorDomainModel model, HealthcheckData healthcheckData)
        {
            healthcheckData.UserAccountData = new HealthcheckAccountData();
            healthcheckData.AdminLastLoginDate = DateBetween2Dates(healthcheckData.DomainCreation, DateTime.Now); ;
            healthcheckData.AdminAccountName = GraphObjectReference.Administrator;
            int size = GetCountFromSize(model);
            for (int i = 0; i < size; i++)
            {
                var x = new MockupADItem();
                x.DistinguishedName = "CN=123";
                // disabled
                x.UserAccountControl += BoolOnChance(15) * 0x00000002;
                //preauth
                x.UserAccountControl += BoolOnChance(1) * 0x400000;
                // locked
                x.UserAccountControl += BoolOnChance(4) * 0x00000010;
                // pwd never expires
                x.UserAccountControl += BoolOnChance(10) * 0x00010000;
                // pwd not required
                x.UserAccountControl += BoolOnChance(2) * 0x00000020;
                // trusted to authenticate
                x.UserAccountControl += BoolOnChance(2) * 0x80000;
                x.PrimaryGroupID = 515 + BoolOnChance(1);
                HealthcheckAnalyzer.ProcessAccountData(healthcheckData.UserAccountData, x, false, default(DateTime));

            }
            healthcheckData.LoginScript = new List<HealthcheckLoginScriptData>();
        }

        private void GenerateComputerData(FakeHealthCheckDataGeneratorDomainModel model, HealthcheckData healthcheckData)
        {
            healthcheckData.OperatingSystem = new List<HealthcheckOSData>();
            healthcheckData.OperatingSystemVersion = new List<HealthcheckOSVersionData>();
            healthcheckData.ComputerAccountData = new HealthcheckAccountData();
            int size = GetCountFromSize(model);
            for (int i = 0; i < size; i++)
            {
                var x = new MockupADItem();
                x.DistinguishedName = "CN=123";
                // disabled
                x.UserAccountControl += BoolOnChance(15) * 0x00000002;
                //preauth
                x.UserAccountControl += BoolOnChance(1) * 0x400000;
                // locked
                x.UserAccountControl += BoolOnChance(4) * 0x00000010;
                // pwd never expires
                x.UserAccountControl += BoolOnChance(10) * 0x00010000;
                // pwd not required
                x.UserAccountControl += BoolOnChance(2) * 0x00000020;
                // trusted to authenticate
                x.UserAccountControl += BoolOnChance(2) * 0x80000;
                x.PrimaryGroupID = 515 + BoolOnChance(1);
                HealthcheckAnalyzer.ProcessAccountData(healthcheckData.ComputerAccountData, x, true, default(DateTime));
            }
            healthcheckData.LoginScript = new List<HealthcheckLoginScriptData>();

            healthcheckData.DomainControllers = new List<HealthcheckDomainController>();
            size = (int)Math.Exp(Math.Log10(size) / 2);
            if (size < 1)
                size = 1;
            for (int i = 0; i < size; i++)
            {
                HealthcheckDomainController dc = new HealthcheckDomainController();
                dc.DCName = "DC" + i;
                dc.CreationDate = DateBetween2Dates(healthcheckData.DomainCreation, DateTime.Now);
                // last logon timestam can have a delta of 14 days
                dc.LastComputerLogonDate = DateTime.Now.AddDays(-1 * rnd.Next(180));
                dc.DistinguishedName = "DC=DC";
                dc.OperatingSystem = "Windows 2019";
                healthcheckData.DomainControllers.Add(dc);
            }
        }

        private static int BoolOnChance(int percent)
        {
            return rnd.Next(100 + percent) / 100;
        }

        private static int GetCountFromSize(FakeHealthCheckDataGeneratorDomainModel model)
        {
            int upperBound, lowerBound;
            switch (model.Size)
            {
                case DomainSizeModel.Large:
                    lowerBound = 10000;
                    upperBound = 100000;
                    break;
                case DomainSizeModel.Medium:
                    lowerBound = 1000;
                    upperBound = 10000;
                    break;
                case DomainSizeModel.Small:
                default:
                    lowerBound = 100;
                    upperBound = 1000;
                    break;
                case DomainSizeModel.VerySmall:
                    lowerBound = 10;
                    upperBound = 100;
                    break;
            }
            return rnd.Next(lowerBound, upperBound);
        }

        private static void GenerateGeneralData(FakeHealthCheckDataGeneratorDomainModel model, HealthcheckData healthcheckData)
        {
            string fqdn;
            if (model.Forest == null)
            {
                fqdn = FQDNGenerator();
                healthcheckData.ForestFQDN = fqdn;
            }
            else
            {
                fqdn = ChildGenerator() + "." + model.Forest.ForestFQDN;
                healthcheckData.ForestFQDN = model.Forest.ForestFQDN;
            }

            healthcheckData.DomainFQDN = fqdn;

            healthcheckData.DomainSid = GenerateRandomSid();

            if (model.Forest != null)
            {
                healthcheckData.DomainCreation = DateBetween2Dates(model.Forest.DomainCreation, DateTime.Now);
                healthcheckData.ForestFunctionalLevel = model.Forest.ForestFunctionalLevel;
            }
            else
            {
                healthcheckData.DomainCreation = DateTime.Now.AddYears(-5).AddDays(-1 * rnd.Next(10 * 365));
                healthcheckData.ForestFunctionalLevel = rnd.Next(0, 8);
            }

            // adding the domain Netbios name
            healthcheckData.NetBIOSName = healthcheckData.DomainFQDN.Split('.')[0];


            healthcheckData.DomainFunctionalLevel = rnd.Next(healthcheckData.ForestFunctionalLevel, 8);
            healthcheckData.SchemaVersion = SchemaVersion(healthcheckData.ForestFunctionalLevel);
            healthcheckData.SchemaInternalVersion = 1;
            healthcheckData.SchemaLastChanged = DateBetween2Dates(healthcheckData.DomainCreation, DateTime.Now);
            healthcheckData.GenerationDate = DateTime.Now;

            healthcheckData.IsRecycleBinEnabled = true;

            Version version = Assembly.GetExecutingAssembly().GetName().Version;
            healthcheckData.EngineVersion = version.ToString(4);
            healthcheckData.Level = PingCastleReportDataExportLevel.Full;
        }

        private static int SchemaVersion(int forestFunctionalLevel)
        {
            switch (forestFunctionalLevel)
            {
                case 0: return 13;
                case 1: return 30;
                case 2: return 31;
                case 3: return 44;
                case 4: return 47;
                case 5: return 56;
                case 6: return 69;
                default:
                case 7: return 87;
            }
        }

        private static DateTime DateBetween2Dates(DateTime start, DateTime end)
        {
            TimeSpan timeSpan = end - start;
            TimeSpan newSpan = new TimeSpan(0, rnd.Next(0, (int)timeSpan.TotalMinutes), 0);
            DateTime newDate = start + newSpan;
            return newDate;
        }

        private static string GenerateRandomSid()
        {
            return "S-1-5-21-" + rnd.Next(2147483647) + "-" + rnd.Next(2147483647) + "-" + rnd.Next(2147483647);
        }
    }
}
