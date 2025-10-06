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
using System.Diagnostics;
using System.Resources;
using System.Xml.Serialization;

namespace PingCastle.Rules
{
    public abstract class RuleBase<T> : IRuleScore
    {
        protected const int maxNumDisplayAccount = 100;
        private static Dictionary<string, ResourceManager> _resourceManagers = new Dictionary<string, ResourceManager>(2);

        public string RiskId { get; set; }
        public string Title { get; private set; }
        public string Notice { get; protected set; }
        public string NoticeTooltip { get; protected set; }
        public string Description { get; private set; }
        public string TechnicalExplanation { get; private set; }
        public string Solution { get; private set; }
        public string Documentation { get; private set; }
        public string RelevantProducts { get; private set; }
        public RiskRuleCategory Category { get; set; }
        public RiskModelCategory Model { get; set; }
        private string DetailRationale;
        protected string DetailFormatString;
        // used to provide a location of the data in the report (aka a link to the report)
        public string ReportLocation { get; private set; }

        public int Points { get; set; }
        public string Rationale { get; set; }

        public List<string> Details { get; set; }

        public List<ExtraDetail> ExtraDetails { get; set; }

        public int MaturityLevel { get; set; }

        protected Dictionary<string, string> ReplacementToDo = new Dictionary<string, string>();

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

        private ResourceManager _resourceManager;
        protected ResourceManager ResourceManager => _resourceManager ??= InitResourceManager();


        private ResourceManager InitResourceManager()
        {
            var currentType = GetType();
            var @namespace = currentType.Namespace;
            if (!_resourceManagers.TryGetValue(@namespace, out var resourceManager))
            {
                resourceManager = new ResourceManager($"{@namespace}.RuleDescription", currentType.Assembly);
                _resourceManagers[@namespace] = resourceManager;
            }

            return resourceManager;
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
            ReloadResource();
        }

        public void ReloadResource()
        {
            string resourceKey;
            resourceKey = RiskId.Replace('-', '_').Replace('$', '_');

            Title = ResourceManager.GetString(resourceKey + "_Title");
            Description = ResourceManager.GetString(resourceKey + "_Description");
            TechnicalExplanation = ResourceManager.GetString(resourceKey + "_TechnicalExplanation");
            RelevantProducts = ResourceManager.GetString(resourceKey + "_RelevantProducts");
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

        public void AddExtraDetail(ExtraDetail detail)
        {
            if (ExtraDetails == null)
                ExtraDetails = new List<ExtraDetail>();

            ExtraDetails.Add(detail);
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
                if (valueReturnedByAnalysis == int.MaxValue)
                {
                    Rationale = Rationale.Replace("{count}", "Infinite");
                }
                else
                {
                    Rationale = Rationale.Replace("{count}", valueReturnedByAnalysis.ToString());
                }
                Rationale = Rationale.Replace("{threshold}", computation.Threshold.ToString());
                foreach (var data in ReplacementToDo)
                {
                    Rationale = Rationale.Replace(data.Key, data.Value);
                }
            }
        }

        public string GetComputationModelString()
        {
            return RuleComputationAttribute.GetComputationModelString(RuleComputation);
        }

        // based on GPO Data, filter only GPO that are applied
        protected Dictionary<IGPOReference, X> ApplyGPOPrority2<X>(HealthcheckData healthcheckData, Dictionary<IGPOReference, X> GPOData)
        {
            // get GPO applied
            var output = ApplyGPOPrority(healthcheckData, GPOData);

            // remove the application to the GPO output (for simplified analysis)
            var output2 = new Dictionary<IGPOReference, X>();
            foreach (var entry in output)
            {
                if (!output2.ContainsKey(entry.Value.Key))
                {
                    output2[entry.Value.Key] = entry.Value.Value;
                }
            }
            return output2;
        }

        // based on GPO Data, filter only GPO that are applied
        // most detailled ouput
        protected Dictionary<string, KeyValuePair<IGPOReference, X>> ApplyGPOPrority<X>(HealthcheckData healthcheckData, Dictionary<IGPOReference, X> GPOData)
        {
            var GPOData2 = new Dictionary<GPOInfo, X>();
            // step 1: skip GPO not applied or disabled
            Trace.WriteLine("Step 1: GPO matches");
            foreach (var entry in GPOData)
            {
                if (healthcheckData.GPOInfoDic == null || !healthcheckData.GPOInfoDic.ContainsKey(entry.Key.GPOId))
                {
                    continue;
                }
                var refGPO = healthcheckData.GPOInfoDic[entry.Key.GPOId];
                if (refGPO.IsDisabled)
                {
                    continue;
                }
                if (refGPO.AppliedTo == null || refGPO.AppliedTo.Count == 0)
                {
                    continue;
                }
                Trace.WriteLine("Step 1: " + refGPO.GPOName);
                GPOData2[refGPO] = entry.Value;
            }
            Trace.WriteLine("Step 1: dump");
            foreach (var a in GPOData2)
            {
                Trace.WriteLine("Step 1: GPO " + a.Key.GPOName);
                foreach (var b in a.Key.AppliedTo)
                {
                    Trace.WriteLine("Step 1:       applied to : " + b);
                }
            }
            // step2: project to the OU where the GPO is applied
            Trace.WriteLine("Step 2: projection");
            var applied = new Dictionary<string, Dictionary<int, KeyValuePair<IGPOReference, X>>>();
            foreach (var v in GPOData2.Keys)
            {
                for (int i = 0; i < v.AppliedTo.Count; i++)
                {
                    var a = v.AppliedTo[i];
                    int order = 0;
                    if (v.AppliedOrder != null && v.AppliedOrder.Count > i)
                    {
                        order = v.AppliedOrder[i];
                    }
                    if (!applied.ContainsKey(a))
                        applied[a] = new Dictionary<int, KeyValuePair<IGPOReference, X>>();
                    applied[a][order] = new KeyValuePair<IGPOReference, X>(v, GPOData2[v]);
                }
            }
            foreach (var a in applied)
            {
                Trace.WriteLine("Step 2: OU " + a.Key);
                foreach (var b in a.Value)
                {
                    Trace.WriteLine("Step 2:       Order : " + b.Key + " GPO: " + b.Value.Key.GPOName);
                }
            }

            // step3: keep only the GPO with the most priority
            Trace.WriteLine("Step 3: projection");
            var applied2 = new Dictionary<string, KeyValuePair<IGPOReference, X>>();
            foreach (var a in applied.Keys)
            {
                var max = 0;
                object w = null;
                foreach (var v in applied[a])
                {
                    if (v.Key > max)
                    {
                        max = v.Key;
                        w = v.Value;
                    }
                }
                if (w != null)
                {
                    applied2[a] = (KeyValuePair<IGPOReference, X>)w;
                }
            }
            foreach (var i in applied2)
            {
                Trace.WriteLine("Step 3: " + i.Key + " gpo " + i.Value.Key.GPOName);
            }
            return applied2;
        }
    }
}
