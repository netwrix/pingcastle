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
    [AttributeUsage(AttributeTargets.Class, Inherited = false)]
    public class HeatlcheckRuleModelAttribute : Attribute
    {
        public HeatlcheckRuleModelAttribute(string Id, HealthcheckRiskRuleCategory Category, HealthcheckRiskModelCategory Model)
        {
            this.Id = Id;
            this.Category = Category;
            this.Model = Model;
        }

        public string Id { get; private set; }
        public HealthcheckRiskRuleCategory Category { get; private set; }
        public HealthcheckRiskModelCategory Model { get; private set; }
    }

    public enum RuleComputationType
    {
        TriggerOnThreshold,
        TriggerOnPresence,
        PerDiscover,
        PerDiscoverWithAMinimumOf,
        TriggerIfLessThan,
    }

    [AttributeUsage(AttributeTargets.Class, Inherited = false, AllowMultiple = true)]
    public class HeatlcheckRuleComputationAttribute : Attribute
    {
        public HeatlcheckRuleComputationAttribute(RuleComputationType ComputationType, int Score, int Threshold = 0, int Order = 1)
        {
            this.ComputationType = ComputationType;
            this.Score = Score;
            this.Threshold = Threshold;
            this.Order = Order;
        }

        public RuleComputationType ComputationType { get; private set; }
        public int Score { get; private set; }
        public int Threshold { get; private set; }
        public int Order { get; private set; }

        public bool HasMatch(int value, ref int points)
        {
            switch (ComputationType)
            {
                case RuleComputationType.TriggerOnPresence:
                    if (value > 0)
                    {
                        points = Score;
                        return true;
                    }
                    return false;
                case RuleComputationType.PerDiscoverWithAMinimumOf:
                    if (value > 0)
                    {
                        points = value * Score;
                        if (points < Threshold)
                            points = Threshold;
                        return true;
                    }
                    return false;
                case RuleComputationType.PerDiscover:
                    if (value > 0)
                    {
                        points = value * Score;
                        return true;
                    }
                    return false;
                case RuleComputationType.TriggerOnThreshold:
                    if (value >= Threshold)
                    {
                        points = Score;
                        return true;
                    }
                    return false;
                case RuleComputationType.TriggerIfLessThan:
                    if (value < Threshold)
                    {
                        points = Score;
                        return true;
                    }
                    return false;
                default:
                    throw new NotImplementedException();
            }
        }
    }

    public interface IHeatlcheckRuleFrameworkReference
    {
        string URL
        {
            get;
        }
        string Label
        {
            get;
        }
    }

    [AttributeUsage(AttributeTargets.Class, Inherited = false)]
    public class HeatlcheckRuleSTIGAttribute : Attribute, IHeatlcheckRuleFrameworkReference
    {
        public HeatlcheckRuleSTIGAttribute(string id, bool forest = false)
        {
            ID = id;
            ForestCheck = forest;
        }

		public string ID { get; private set; }
		public bool ForestCheck { get; private set; }

        public string URL { get
            {
                if (ForestCheck)
                    return "https://www.stigviewer.com/stig/active_directory_forest/2016-12-19/finding/" + ID;
                return "https://www.stigviewer.com/stig/active_directory_domain/2017-12-15/finding/" + ID;
            }
        }

		public string Label { get { return "STIG " + ID; } }
    }
}
