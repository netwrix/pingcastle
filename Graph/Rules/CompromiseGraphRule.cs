using PingCastle.Data;
using PingCastle.Rules;
using System;
using System.Collections.Generic;
using System.Resources;
using System.Text;

namespace PingCastle.Graph.Rules
{
	public abstract class CompromiseGraphRule : RuleBase<CompromiseGraphData>
	{
		public Dictionary<string, CompromiseGraphRuleDetail> ImpactedGraph { get; set; }

		private readonly string GraphRationale;

		public CompromiseGraphRule() : base()
		{
			ImpactedGraph = new Dictionary<string, CompromiseGraphRuleDetail>();
			var resourceKey = RiskId.Replace('-', '_').Replace('$', '_');
			GraphRationale = ResourceManager.GetString(resourceKey + "_GraphRationale");
		}

		public void AddGraph(SingleCompromiseGraphData graphData)
		{
			if (!ImpactedGraph.ContainsKey(graphData.Name))
			{
				var detail = new CompromiseGraphRuleDetail();
				detail.Details = new List<string>();
				ImpactedGraph.Add(graphData.Name, detail);
			}
			string ruleDetail = String.Format("{1} ({0})", graphData.Name, graphData.Description);
			if (!Details.Contains(ruleDetail))
				Details.Add(ruleDetail);
		}

		public void AddGraphRawDetail(SingleCompromiseGraphData graphData, params object[] data)
		{
			AddGraph(graphData);
			ImpactedGraph[graphData.Name].Details.Add(String.Format(DetailFormatString, data));
			
		}

		protected override void UpdateLabelsAfterMatch(int valueReturnedByAnalysis, RuleComputationAttribute computation)
		{
			base.UpdateLabelsAfterMatch(valueReturnedByAnalysis, computation);
			if (GraphRationale != null)
			{
				foreach (var detail in ImpactedGraph.Values)
				{
					detail.Rationale = GraphRationale.Replace("{count}", detail.Details.Count.ToString());
				}
			}
		}
	}

	public class CompromiseGraphRuleDetail
	{
		public string Rationale { get; set; }
		public List<string> Details { get; set; }
	}
}
