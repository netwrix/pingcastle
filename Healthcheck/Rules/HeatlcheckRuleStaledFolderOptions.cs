//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Rules;
using System.Collections.Generic;

namespace PingCastle.Healthcheck.Rules
{
    [RuleModel("S-FolderOptions", RiskRuleCategory.StaleObjects, RiskModelCategory.ObjectConfig)]
    [RuleComputation(RuleComputationType.TriggerOnPresence, 0)]
    [RuleMitreAttackMitigation(MitreAttackMitigation.ActiveDirectoryConfiguration)]
    [RuleMaturityLevel(5)]
    [RuleIntroducedIn(3, 3)]
    public class HeatlcheckRuleStaledFolderOptions : RuleBase<HealthcheckData>
    {
        protected override int? AnalyzeDataNew(HealthcheckData healthcheckData)
        {
            var dangerousFileExtensions = new string[] { "js", "jse", "vbs", "vbe", "vb", "wsh", "wsf" };
            var found = new List<string>();
            if (healthcheckData.GPOFolderOptions != null)
            {
                foreach (var option in healthcheckData.GPOFolderOptions)
                {
                    if (!found.Contains(option.FileExt.ToLowerInvariant()))
                        found.Add(option.FileExt.ToLowerInvariant());
                }
            }
            foreach (var ext in dangerousFileExtensions)
            {
                if (!found.Contains(ext))
                {
                    AddRawDetail(ext, "Not found in Folder Options");
                }
            }
            return null;
        }
    }
}
