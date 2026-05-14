//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
namespace PingCastle.Healthcheck.Rules
{
    using PingCastle.Rules;
    using PingCastle.Scanners;
    using System.Diagnostics;

    [RuleModel("S-Vuln-MS14-068", RiskRuleCategory.StaleObjects, RiskModelCategory.VulnerabilityManagement)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 100)]
    [RuleCERTFR("CERTFR-2014-ALE-011")]
    [RuleMaturityLevel(1)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.UpdateSoftware)]
    public class HeatlcheckRuleStaledMS14_068 : RuleBase<HealthcheckData>
    {
        private readonly KerberosChecksumVulnerabilityScanner Scanner;

        public HeatlcheckRuleStaledMS14_068(KerberosChecksumVulnerabilityScanner scanner)
        {
            Scanner = scanner;
        }

        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.DomainControllers != null && healthcheckData.DomainControllers.Count > 0)
            {
                foreach (var domainController in healthcheckData.DomainControllers)
                {
                    if (healthcheckData.IsPrivilegedMode)
                    {
                        if (domainController.AzureADKerberos)
                        {
                            continue;
                        }

                        Trace.WriteLine("S-Vuln-MS14-068: In Privileged mode, running scanner.");
                        var scanResult = Scanner.Scan(
                            domainController.DCName,
                            domainController.OperatingSystem,
                            domainController.InstalledHotFixes,
                            domainController.StartupTime,
                            domainController.OperatingSystemVersion,
                            domainController.MostRecentQualityUpdateDate);

                        if (scanResult.IsVulnerable)
                        {
                            AddRawDetail(domainController.DCName, scanResult.Reason, domainController.OperatingSystem);
                        }
                    }
                    else
                    {
                        Trace.WriteLine("S-Vuln-MS14-068: In Standard mode, NOT running scanner.");
                    }
                }
            }

            return null;
        }
    }
}