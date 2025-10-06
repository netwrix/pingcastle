using PingCastle.Cloud.Data;
using PingCastle.Healthcheck;
using PingCastle.Rules;
using System.Text;

namespace PingCastle.Report
{
    public interface IActionPlan
    {
        void GenerateMainActionPlan(StringBuilder sb, Healthcheck.HealthcheckRiskRule rule, Rules.RuleBase<HealthcheckData> hcrule);

        void GenerateDetailledActionPlan(StringBuilder sb, HealthcheckRiskRule rule, Rules.RuleBase<HealthcheckData> hcrule, string d);
    }

    public interface IAADActionPlan
    {
        void GenerateMainActionPlan(StringBuilder sb, HealthCheckCloudDataRiskRule rule, RuleBase<HealthCheckCloudData> hcrule);
        void GenerateDetailledActionPlan(StringBuilder sb, HealthCheckCloudDataRiskRule rule, RuleBase<HealthCheckCloudData> hcrule, string d);

    }


    public interface IActionPlanConsolidation : IActionPlan
    {
        void LoadDomain(HealthcheckData data);
    }
}
