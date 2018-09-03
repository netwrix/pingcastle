//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.Reflection;
using System.Resources;
using System.Text;
using System.Text.RegularExpressions;

namespace PingCastle.Healthcheck.Rules
{
    public abstract class HeatlcheckRuleBase
    {
		public string Id { get; set; }
		public string Title { get; private set; }
		public string Description { get; private set; }
		public string TechnicalExplanation { get; private set; }
		public string Solution { get; private set; }
		public string Documentation { get; private set; }
		public HealthcheckRiskRuleCategory Category { get; set; }
		public HealthcheckRiskModelCategory Model { get; set; }
		private string DetailRationale;
		private string DetailFormatString;

        public int Points { get; set; }
        public string Rationale { get; set; }

        public List<string> Details { get; set; }

		// return count if not null or rely on details.count
		protected virtual int? AnalyzeDataNew(HealthcheckData healthcheckData)
		{
			throw new NotImplementedException();
		}

		protected virtual int? AnalyzeDataNew(HealthcheckData healthcheckData, ICollection<DomainKey> AllowedMigrationDomains)
		{
			if (AllowedMigrationDomains == null)
				return AnalyzeDataNew(healthcheckData);
			throw new NotImplementedException();
		}

		private List<HeatlcheckRuleComputationAttribute> RuleComputation;

        ResourceManager _resourceManager;
        ResourceManager ResourceManager
        {
            get
            {
                if (_resourceManager == null)
                {
                    _resourceManager = new ResourceManager("PingCastle.Healthcheck.Rules.RuleDescription", typeof(HeatlcheckRuleBase).Assembly);
                }
                return _resourceManager;
            }
        }

        protected HeatlcheckRuleBase()
        {
			object[] models = GetType().GetCustomAttributes(typeof(HeatlcheckRuleModelAttribute), true);
			if (models == null || models.Length == 0)
				throw new NotImplementedException();
			HeatlcheckRuleModelAttribute model = (HeatlcheckRuleModelAttribute) models[0];
			string resourceKey;
            Id = model.Id;
			resourceKey = Id.Replace('-', '_').Replace('$', '_');

            Category = model.Category;
            Model = model.Model;
			Title = ResourceManager.GetString(resourceKey + "_Title");
			Description = ResourceManager.GetString(resourceKey + "_Description");
			TechnicalExplanation = ResourceManager.GetString(resourceKey + "_TechnicalExplanation");
			Solution = ResourceManager.GetString(resourceKey + "_Solution");
			Documentation = ResourceManager.GetString(resourceKey + "_Documentation");
			DetailRationale = ResourceManager.GetString(resourceKey + "_Rationale");
			DetailFormatString = ResourceManager.GetString(resourceKey + "_Detail");

            if (!String.IsNullOrEmpty(Documentation))
            {
                string[] lines = Documentation.Split(
                        new[] { "\r\n", "\r", "\n" },
                        StringSplitOptions.None
                    );
                for (int i = 0; i < lines.Length; i++)
                {
                    lines[i] = "<a href=\"" + lines[i] + "\">" + lines[i] + "</a>";
                }
                Documentation = string.Join("<br>\r\n", lines);
            }
            object[] frameworks = GetType().GetCustomAttributes(typeof(IHeatlcheckRuleFrameworkReference), true);
            if (frameworks != null && frameworks.Length != 0)
            {
                if (!String.IsNullOrEmpty(Documentation))
                    Documentation += "<br>\r\n";
                for (int i = 0; i < frameworks.Length; i++)
                {
                    if (i > 0)
                        Documentation += "<br>\r\n";
                    Documentation += "<a href=\"" + ((IHeatlcheckRuleFrameworkReference) frameworks[i]).URL + "\">" + ((IHeatlcheckRuleFrameworkReference)frameworks[i]).Label + "</a>";
                }
            }


                RuleComputation = new List<HeatlcheckRuleComputationAttribute>((HeatlcheckRuleComputationAttribute[])GetType().GetCustomAttributes(typeof(HeatlcheckRuleComputationAttribute), true));
			if (RuleComputation.Count == 0)
				throw new NotImplementedException();
			RuleComputation.Sort((HeatlcheckRuleComputationAttribute a, HeatlcheckRuleComputationAttribute b)
				=> 
				{
					return a.Order.CompareTo(b.Order);
				}
			);
        }

        public void Initialize()
        {
            Details = null;
        }

        public void AddDetail(string detail)
        {
            if (Details == null)
                Details = new List<string>();
            Details.Add(detail);
        }

        public void AddRawDetail(params object[] data)
        {
			AddDetail(String.Format(DetailFormatString, data));
        }

		public bool Analyze(HealthcheckData healthcheckData)
		{
			return Analyze(healthcheckData, null);
		}

		public bool Analyze(HealthcheckData healthcheckData, ICollection<DomainKey> AllowedMigrationDomains)
        {
			bool hasTheRuleMatched = false;
			// PingCastle 2.5
            Points = 0;
			int? valueReturnedByAnalysis = AnalyzeDataNew(healthcheckData, AllowedMigrationDomains);
			if (valueReturnedByAnalysis == null)
			{
				valueReturnedByAnalysis = 0;
				if (Details != null)
					valueReturnedByAnalysis = Details.Count;
			}
			foreach (var computation in RuleComputation)
			{
				int points = 0;
				if (computation.HasMatch((int) valueReturnedByAnalysis, ref points))
				{
					hasTheRuleMatched = true;
					Points = points;
					if (DetailRationale != null)
					{
						Rationale = DetailRationale;
						Rationale = Rationale.Replace("{count}", valueReturnedByAnalysis.ToString());
						Rationale = Rationale.Replace("{threshold}", computation.Threshold.ToString());
					}
					break;
				}
			}
            return hasTheRuleMatched;
        }

		public string GetComputationModelString()
		{
			StringBuilder sb = new StringBuilder();
			for (int i = 0; i < RuleComputation.Count; i++ )
			{
				if (i > 0)
					sb.Append("\r\nthen ");
				var rule = RuleComputation[i];
				switch (rule.ComputationType)
				{
					case RuleComputationType.TriggerOnThreshold:
						sb.Append(rule.Score);
						sb.Append(" points if the occurence is greater or equals than ");
						sb.Append(rule.Threshold);
						break;
					case RuleComputationType.TriggerOnPresence:
                        if (rule.Score > 0)
                        {
                            sb.Append(rule.Score);
                            sb.Append(" points if present");
                        }
                        else
                        {
                            sb.Append("Informative rule (0 point)");
                        }
						break;
					case RuleComputationType.PerDiscover:
						sb.Append(rule.Score);
						sb.Append(" points per discovery");
						break;
					case RuleComputationType.PerDiscoverWithAMinimumOf:
						sb.Append(rule.Score);
						sb.Append(" points per discovery with a minimal of ");
						sb.Append(rule.Threshold);
						sb.Append(" points");
						break;
					case RuleComputationType.TriggerIfLessThan:
						sb.Append(rule.Score);
						sb.Append(" points if the occurence is strictly lower than ");
						sb.Append(rule.Threshold);
						break;
				}
			}
			return sb.ToString();
		}
    }
}
