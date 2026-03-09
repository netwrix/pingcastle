namespace PingCastle.Healthcheck.Rules
{
    using PingCastle.Rules;
    using PingCastle.Scanners;
    using System.Diagnostics;

    [RuleModel("S-Vuln-MS17_010", RiskRuleCategory.StaleObjects, RiskModelCategory.VulnerabilityManagement)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 100)]
    [RuleCERTFR("CERTFR-2017-ALE-010")]
    [RuleMaturityLevel(1)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.UpdateSoftware)]
    public class HeatlcheckRuleStaledMS17_010 : RuleBase<HealthcheckData>
    {
        public HeatlcheckRuleStaledMS17_010(SmbHotFixVulnerabilityScanner scanner)
        {
            Scanner = scanner;
        }

        private readonly SmbHotFixVulnerabilityScanner Scanner;

        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.DomainControllers == null
                || !healthcheckData.IsPrivilegedMode
                || healthcheckData.DomainControllers.Count == 0)
            {
                return null;
            }

            foreach (var domainController in healthcheckData.DomainControllers)
            {
                if (domainController.AzureADKerberos)
                {
                    Trace.WriteLine("S-Vuln-MS17-010: Skipping Azure AD Kerberos.");
                    continue;
                }

                var scanResult = Scanner.Scan(
                    domainController.DCName,
                    domainController.OperatingSystem,
                    domainController.SupportSMB1,
                    domainController.InstalledHotFixes,
                    domainController.StartupTime);

                if (scanResult.IsVulnerable)
                {
                    AddRawDetail(domainController.DCName, scanResult.Reason, domainController.OperatingSystem);
                }
            }

            return null;
        }
    }
}