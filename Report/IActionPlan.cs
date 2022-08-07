using PingCastle.Healthcheck;
using System;
using System.Collections.Generic;
using System.Text;

namespace PingCastle.Report
{
    public interface IActionPlan
    {
        void GenerateMainActionPlan(StringBuilder sb, Healthcheck.HealthcheckRiskRule rule, Rules.RuleBase<HealthcheckData> hcrule);

        void GenerateDetailledActionPlan(StringBuilder sb, HealthcheckRiskRule rule, Rules.RuleBase<HealthcheckData> hcrule, string d);
    }

    public interface IActionPlanConsolidation : IActionPlan
    {
        void LoadDomain(HealthcheckData data);
    }
}
