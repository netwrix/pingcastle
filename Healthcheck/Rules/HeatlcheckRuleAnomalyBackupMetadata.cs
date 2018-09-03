//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.Text;

namespace PingCastle.Healthcheck.Rules
{
	[HeatlcheckRuleModel("A-BackupMetadata", HealthcheckRiskRuleCategory.Anomalies, HealthcheckRiskModelCategory.Backup)]
	[HeatlcheckRuleComputation(RuleComputationType.TriggerOnThreshold, 15, Threshold: 7)]
    [HeatlcheckRuleSTIG("V-25385")]
    public class HeatlcheckRuleAnomalyBackupMetadata : HeatlcheckRuleBase
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
