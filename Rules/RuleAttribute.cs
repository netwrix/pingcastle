//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Text;

namespace PingCastle.Rules
{
    [AttributeUsage(AttributeTargets.Class, Inherited = false)]
    public class RuleModelAttribute : Attribute
    {
        public RuleModelAttribute(string Id, RiskRuleCategory Category, RiskModelCategory Model)
        {
            this.Id = Id;
            this.Category = Category;
            this.Model = Model;
        }

        public string Id { get; private set; }
        public RiskRuleCategory Category { get; private set; }
        public RiskModelCategory Model { get; private set; }
    }

	[AttributeUsage(AttributeTargets.Class, Inherited = false)]
	public class RuleObjectiveAttribute : Attribute
	{
		public RuleObjectiveAttribute(string Id, RiskRuleCategory Category, RiskModelObjective objective)
		{
			this.Id = Id;
			this.Category = Category;
			this.Objective = objective;
		}

		public string Id { get; private set; }
		public RiskRuleCategory Category { get; private set; }
		public RiskModelObjective Objective { get; private set; }
	}

    public interface IRuleMaturity
    {
        int Level { get; }
    }

	[AttributeUsage(AttributeTargets.Class, Inherited = false)]
	public class RuleIntroducedInAttribute : Attribute
	{
		public RuleIntroducedInAttribute(int major, int minor, int build = 0, int revision = 0)
		{
			Major = major;
			Minor = minor;
			Build = build;
			Revision = revision;
		}

		public int Major { get; private set; }
		public int Minor { get; private set; }
		public int Build { get; private set; }
		public int Revision { get; private set; }

		private Version _version;
		public Version Version
		{
			get
			{
				if (_version == null)
				{
					_version = new Version(Major, Minor, Build, Revision);
				}
				return _version;
			}
		}
	}

	public enum RuleComputationType
    {
        TriggerOnThreshold,
        TriggerOnPresence,
        PerDiscover,
        PerDiscoverWithAMinimumOf,
        TriggerIfLessThan,
		Objective
    }

    [AttributeUsage(AttributeTargets.Class, Inherited = false, AllowMultiple = true)]
    public class RuleComputationAttribute : Attribute
    {
        public RuleComputationAttribute(RuleComputationType ComputationType, int Score, int Threshold = 0, int Order = 1)
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
				case RuleComputationType.Objective:
					if (value != -1)
					{
						points = Score;
						return true;
					}
					points = 0;
					return true;
                default:
                    throw new NotImplementedException();
            }
        }
    }

    public class RuleFrameworkReference: Attribute, IEquatable<RuleFrameworkReference>, IComparable<RuleFrameworkReference>
    {
        public virtual string URL
        {
            get; set;
        }
        public virtual string Label
        {
            get; set;
        }

        public virtual string Country { get; set; }

        public virtual int CompareTo(RuleFrameworkReference other)
        {
            return String.CompareOrdinal(Label, other.Label);
        }

        public virtual bool Equals(RuleFrameworkReference other)
        {
            return String.Equals(Label, other.Label) && String.Equals(URL, other.URL);
        }

        public virtual string GenerateLink()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("<a href=\"");
            sb.Append(URL);
            sb.Append("\">");
            if (!string.IsNullOrEmpty(Country))
            {
                sb.Append("[");
                sb.Append(Country.ToUpperInvariant());
                sb.Append("]");
            }
            sb.Append(Label);
            sb.Append("</a>");
            return sb.ToString();
        }
    }

	public enum STIGFramework
	{
		Domain,
		Forest,
		Windows7,
		Windows10,
		Windows2008,
		ActiveDirectoryService2003,
		ActiveDirectoryService2008
	}

    [AttributeUsage(AttributeTargets.Class, Inherited = false, AllowMultiple= true)]
    public class RuleSTIGAttribute : RuleFrameworkReference
    {
		public RuleSTIGAttribute(string id, string title = null, STIGFramework framework = STIGFramework.Domain)
        {
            ID = id;
			Framework = framework;
			Title = title;
            Country = "us";
        }

		public string ID { get; private set; }
		public STIGFramework Framework { get; private set; }
		public string Title { get; private set; }

        public override string URL
        {
            get
            {
				switch (Framework)
				{
					case STIGFramework.Forest:
						return "https://www.stigviewer.com/stig/active_directory_forest/2016-12-19/finding/" + ID;
					case STIGFramework.Windows7:
						return "https://www.stigviewer.com/stig/windows_7/2012-08-22/finding/" + ID;
					case STIGFramework.Windows10:
						return "https://www.stigviewer.com/stig/windows_10/2018-04-06/finding/" + ID;
					case STIGFramework.Windows2008:
						return "https://www.stigviewer.com/stig/windows_2008_member_server/2018-03-07/finding/" + ID;
					case STIGFramework.ActiveDirectoryService2003:
						return "https://www.stigviewer.com/stig/active_directory_service_2003/2011-05-20/finding/" + ID;
					case STIGFramework.ActiveDirectoryService2008:
						return "https://www.stigviewer.com/stig/active_directory_service_2008/2011-05-23/finding/" + ID;
					default:
						return "https://www.stigviewer.com/stig/active_directory_domain/2017-12-15/finding/" + ID;
				}
            }
        }

        public override string Label { get { return "STIG " + ID + (!String.IsNullOrEmpty(Title) ? " - " + Title : null); } }
    }

	[AttributeUsage(AttributeTargets.Class, Inherited = false, AllowMultiple=true)]
	public class RuleANSSIAttribute : RuleFrameworkReference
	{
		public RuleANSSIAttribute(string id, string location)
		{
			ID = id;
			Location = location;
            Country = "fr";
        }

		public string ID { get; private set; }
		public string Location { get; private set; }

        public override string URL
		{
			get
			{
				return "https://www.ssi.gouv.fr/uploads/IMG/pdf/NP_ActiveDirectory_NoteTech.pdf" + (!String.IsNullOrEmpty(Location) ? "#" + Location : null);
			}
		}

        public override string Label { get { return "ANSSI - Recommandations de sécurité relatives à Active Directory - " + ID + (!String.IsNullOrEmpty(Location) ? " [" + Location + "]" : null); } }
	}

	/*[AttributeUsage(AttributeTargets.Class, Inherited = false, AllowMultiple = true)]
	public class RuleBSIAttribute : RuleFrameworkReference
	{
		public RuleBSIAttribute(string id)
		{
            Country = "de";
            switch (id)
			{
				case "M 2.412":
					ID = "M 2.412 Schutz der Authentisierung beim Einsatz von Active Directory";
					URL = "https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m02/m02412.html?nn=6604968";
					break;
				case "M 4.314":
					ID = "M 4.314 Sichere Richtlinieneinstellungen für Domänen und Domänen-Controller";
					URL = "https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04314.html?nn=6604968";
					break;
				case "M 4.315":
					ID = "M 4.315 Aufrechterhaltung der Betriebssicherheit von Active Directory ";
					URL = "https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04315.html";
					break;
				default:
					throw new NotImplementedException();
			}
		}

		public string ID { get; private set; }

        public override string Label { get { return "BSI " + ID; } }
	}*/

	[AttributeUsage(AttributeTargets.Class, Inherited = false, AllowMultiple = true)]
	public class RuleCERTFRAttribute : RuleFrameworkReference
	{
		public RuleCERTFRAttribute(string id, string section = null)
		{
			ID = id;
			Section = section;
            Country = "fr";
        }

		public string ID { get; private set; }
		public string Section { get; private set; }
        public override string URL
		{
			get
			{
				string path = "https://www.cert.ssi.gouv.fr/actualite/";
				if (ID.Contains("-ALE-"))
					path = "https://www.cert.ssi.gouv.fr/alerte/";
				if (ID.Contains("-INF-"))
					path = "https://www.cert.ssi.gouv.fr/information/";
				return path + ID + (!String.IsNullOrEmpty(Section) ? "/#" + Section : null);
			}
		}

        public override string Label { get { return "ANSSI " + ID; } }
	}

    [AttributeUsage(AttributeTargets.Class, Inherited = false, AllowMultiple = true)]
    public class RuleDurANSSIAttribute : RuleFrameworkReference, IRuleMaturity
    {
        public RuleDurANSSIAttribute(int level, string id, string description)
        {
            ID = id;
            Level = level;
            Country = "fr";
            Label = "ANSSI - " + description + " (vuln" + level + "_" + id + ")";
            ANSSILabel = description;
        }

        public int Level { get; set; }
        public string ID { get; private set; }
        public string ANSSILabel { get; private set; }

        public override string URL
        {
            get
            {
                return "https://www.cert.ssi.gouv.fr/uploads/guide-ad.html#" + ID;
            }
        }

        //public override string Label { get { return "[ANSSI] ID: " + ID; } }

        public override bool Equals(RuleFrameworkReference other)
        {
            if (other is RuleDurANSSIAttribute)
            {
                return String.Equals(Label, other.Label) && String.Equals(URL, other.URL) && Level == ((RuleDurANSSIAttribute)other).Level;
            }
            else
            {
                return base.Equals(other);
            }
        }

        public override string GenerateLink()
        {
            return base.GenerateLink() + "<span class=\"badge grade-" + Level + "\">" + Level + "</span>";
        }
    }

    [AttributeUsage(AttributeTargets.Class, Inherited = false, AllowMultiple = false)]
    public class RuleMaturityLevelAttribute : Attribute, IRuleMaturity
    {
        public RuleMaturityLevelAttribute(int Level)
        {
            this.Level = Level;
        }

        public int Level { get; set; }
    }
}
