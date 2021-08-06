//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;
using System;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("A-BackupMetadata", RiskRuleCategory.Anomalies, RiskModelCategory.Backup)]
    [RuleComputation(RuleComputationType.TriggerOnThreshold, 15, Threshold: 7)]
    [RuleSTIG("V-25385", "Active Directory data must be backed up daily for systems with a Risk Management Framework categorization for Availability of moderate or high. Systems with a categorization of low must be backed up weekly.")]
    [RuleMaturityLevel(3)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.DataBackup)]
    public class HeatlcheckRuleAnomalyBackupMetadata : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            if (healthcheckData.LastADBackup < DateTime.MaxValue)
            {
                return (int)(healthcheckData.GenerationDate - healthcheckData.LastADBackup).TotalDays;
            }
            else if (healthcheckData.LastADBackup == DateTime.MaxValue)
            {
                return (int)(healthcheckData.GenerationDate - healthcheckData.DomainCreation).TotalDays;
            }
            return 0;
        }
    }
}
