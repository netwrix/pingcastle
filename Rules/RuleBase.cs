//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Data;
using PingCastle.Healthcheck;
using System;
using System.Collections.Generic;
using System.IO;
using System.Resources;
using System.Text;
using System.Xml;
using System.Xml.Serialization;

namespace PingCastle.Rules
{
    public abstract class RuleBase<T> : IRuleScore
    {
        public string RiskId { get; set; }
        public string Title { get; private set; }
        public string Description { get; private set; }
        public string TechnicalExplanation { get; private set; }
        public string Solution { get; private set; }
        public string Documentation { get; private set; }
        public RiskRuleCategory Category { get; set; }
        public RiskModelCategory Model { get; set; }
        private string DetailRationale;
        protected string DetailFormatString;
        // used to provide a location of the data in the report (aka a link to the report)
        public string ReportLocation { get; private set; }

        public int Points { get; set; }
        public string Rationale { get; set; }

        public List<string> Details { get; set; }

        public int MaturityLevel { get; set; }

        [XmlIgnore]
        public IInfrastructureSettings InfrastructureSettings { get; set; }

        // return count if not null or rely on details.count
        protected virtual int? AnalyzeDataNew(T healthcheckData)
        {
            throw new NotImplementedException();
        }

        protected virtual int? AnalyzeDataNew(T healthcheckData, ICollection<DomainKey> AllowedMigrationDomains)
        {
            if (AllowedMigrationDomains == null)
                return AnalyzeDataNew(healthcheckData);
            throw new NotImplementedException();
        }

        public List<RuleComputationAttribute> RuleComputation { get; private set; }

        ResourceManager _resourceManager;
        protected ResourceManager ResourceManager
        {
            get
            {
                if (_resourceManager == null)
                {
                    _resourceManager = new ResourceManager(GetType().Namespace + ".RuleDescription", GetType().Assembly);
                }
                return _resourceManager;
            }
        }

        protected RuleBase()
        {
            object[] models = GetType().GetCustomAttributes(typeof(RuleModelAttribute), true);
            if (models != null && models.Length != 0)
            {
                RuleModelAttribute model = (RuleModelAttribute)models[0];
                Category = model.Category;
                Model = model.Model;
                RiskId = model.Id;
            }
            else
            {
                throw new NotImplementedException();
            }
            string resourceKey;
            resourceKey = RiskId.Replace('-', '_').Replace('$', '_');

            Title = ResourceManager.GetString(resourceKey + "_Title");
            Description = ResourceManager.GetString(resourceKey + "_Description");
            TechnicalExplanation = ResourceManager.GetString(resourceKey + "_TechnicalExplanation");
            Solution = ResourceManager.GetString(resourceKey + "_Solution");
            Documentation = ResourceManager.GetString(resourceKey + "_Documentation");
            DetailRationale = ResourceManager.GetString(resourceKey + "_Rationale");

            DetailFormatString = ResourceManager.GetString(resourceKey + "_Detail");
            ReportLocation = ResourceManager.GetString(resourceKey + "_ReportLocation");

            RuleComputation = new List<RuleComputationAttribute>((RuleComputationAttribute[])GetType().GetCustomAttributes(typeof(RuleComputationAttribute), true));
            if (RuleComputation.Count == 0)
                throw new NotImplementedException();
            RuleComputation.Sort((RuleComputationAttribute a, RuleComputationAttribute b)
                =>
            {
                return a.Order.CompareTo(b.Order);
            }
            );
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
            object[] frameworks = GetType().GetCustomAttributes(typeof(RuleFrameworkReference), true);
            if (frameworks != null && frameworks.Length != 0)
            {
                if (!String.IsNullOrEmpty(Documentation))
                    Documentation += "<br>\r\n";
                for (int i = 0; i < frameworks.Length; i++)
                {
                    if (i > 0)
                        Documentation += "<br>\r\n";
                    Documentation += ((RuleFrameworkReference)frameworks[i]).GenerateLink();
                }
            }

            var ruleMaturity = new List<IRuleMaturity>((IRuleMaturity[])GetType().GetCustomAttributes(typeof(IRuleMaturity), true));
            if (ruleMaturity.Count == 0)
            {
                MaturityLevel = 0;
            }
            MaturityLevel = 6;
            foreach (var m in ruleMaturity)
            {
                if (MaturityLevel > m.Level)
                    MaturityLevel = m.Level;
            }
        }

        public void Initialize()
        {
            Details = new List<string>();
        }

        public void AddDetail(string detail)
        {
            Details.Add(detail);
        }

        public void AddRawDetail(params object[] data)
        {
            AddDetail(String.Format(DetailFormatString, data));
        }

        public bool Analyze(T healthcheckData)
        {
            return Analyze(healthcheckData, null);
        }

        public bool Analyze(T data, ICollection<DomainKey> AllowedMigrationDomains)
        {
            bool hasTheRuleMatched = false;
            // PingCastle 2.5
            Points = 0;
            int? valueReturnedByAnalysis = AnalyzeDataNew(data, AllowedMigrationDomains);
            if (valueReturnedByAnalysis == null)
            {
                valueReturnedByAnalysis = 0;
                if (Details != null)
                    valueReturnedByAnalysis = Details.Count;
            }
            foreach (var computation in RuleComputation)
            {
                int points = 0;
                if (computation.HasMatch((int)valueReturnedByAnalysis, ref points))
                {
                    hasTheRuleMatched = true;
                    Points = points;
                    UpdateLabelsAfterMatch((int)valueReturnedByAnalysis, computation);
                    break;
                }
            }
            return hasTheRuleMatched;
        }

        public bool ReAnalyzePartialDetails(int count)
        {
            bool hasTheRuleMatched = false;
            foreach (var computation in RuleComputation)
            {
                int points = 0;
                if (computation.HasMatch(count, ref points))
                {
                    hasTheRuleMatched = true;
                    Points = points;
                    UpdateLabelsAfterMatch(count, computation);
                    break;
                }
            }
            return hasTheRuleMatched;
        }

        protected virtual void UpdateLabelsAfterMatch(int valueReturnedByAnalysis, RuleComputationAttribute computation)
        {
            if (DetailRationale != null)
            {
                Rationale = DetailRationale;
                Rationale = Rationale.Replace("{count}", valueReturnedByAnalysis.ToString());
                Rationale = Rationale.Replace("{threshold}", computation.Threshold.ToString());
            }
        }

        public string GetComputationModelString()
        {
            return RuleComputationAttribute.GetComputationModelString(RuleComputation);
        }
    }
}
