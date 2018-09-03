//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.template;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Text;

namespace PingCastle.Healthcheck
{
    public abstract class HealthCheckReportBase
    {

        protected StringBuilder sb = new StringBuilder();
        public delegate string GetUrlDelegate(DomainKey domainKey, string displayName);
        public delegate bool HasDomainAmbigousNameDelegate(DomainKey domainKey);

        public GetUrlDelegate GetUrlCallback { get; set; }
        public HasDomainAmbigousNameDelegate HasDomainAmbigousName { get; set; }

        public string GenerateReportFile(string filename)
        {
            string html = TemplateManager.LoadResponsiveTemplate();

            html = html.Replace("<%=Title%>", GenerateTitleInformation());
            html = html.Replace("<%=Header%>", GenerateHeaderInformation());

            html = html.Replace("<%=Body%>", GenerateBodyInformation());
            html = html.Replace("<%=Footer%>", GenerateFooterInformation());
            Hook(ref html);
            File.WriteAllText(filename, html);
            return html;
        }

        protected virtual void Hook(ref string html)
        {

        }

        protected void Add(int value)
        {
            sb.Append(value);
        }

        protected void Add(bool value)
        {
            sb.Append(value);
        }

        protected void Add(string text)
        {
            sb.Append(text);
        }

        protected void Add(DateTime date)
        {
            sb.Append(date.ToString("u"));
        }

        public override string ToString()
        {
            return sb.ToString();
        }

        protected delegate void GenerateContentDelegate();

        protected abstract string GenerateFooterInformation();

        protected abstract string GenerateTitleInformation();

        protected abstract string GenerateHeaderInformation();

        protected abstract string GenerateBodyInformation();

        public static bool NoContainer = false;

        public static string GetStyleSheetTheme()
        {
            return @"
<!-- Custom styles for this template -->
<style type=""text/css"">

body { 
	background:#e1e1e1;
    padding-top: 50px;
}
h1, h2, h3, h4
{
color: #Fa9C1A;
}
#wrapper {
	box-shadow:0 0 8px rgba(0,0,0,0.25);
}
#wrapper.well {
	background:#fff;
	border-radius:0;
}

/* navbar */
.navbar-brand
{
    margin: 0;
    padding: 0;
}

.navbar-brand img
{
    max-height: 100%;
}

.navbar-default {
  background-color: #ffffff;
  border-color: #fa9c1a;
}
.navbar-default .navbar-brand {
  color: #58595b;
}
.navbar-default .navbar-brand:hover,
.navbar-default .navbar-brand:focus {
  color: #ffffff;
}
.navbar-default .navbar-text {
  color: #58595b;
}
.navbar-default .navbar-nav > li > a {
  color: #58595b;
}
.navbar-default .navbar-nav > li > a:hover,
.navbar-default .navbar-nav > li > a:focus {
  color: #A7A9AC;
}
.navbar-default .navbar-nav > li > .dropdown-menu {
  background-color: #ffffff;
}
.navbar-default .navbar-nav > li > .dropdown-menu > li > a {
  color: #58595b;
}
.navbar-default .navbar-nav > li > .dropdown-menu > li > a:hover,
.navbar-default .navbar-nav > li > .dropdown-menu > li > a:focus {
  color: #ffffff;
  background-color: #fa9c1a;
}
.navbar-default .navbar-nav > li > .dropdown-menu > li.divider {
  background-color: #fa9c1a;
}
.navbar-default .navbar-nav .open .dropdown-menu > .active > a,
.navbar-default .navbar-nav .open .dropdown-menu > .active > a:hover,
.navbar-default .navbar-nav .open .dropdown-menu > .active > a:focus {
  color: #ffffff;
  background-color: #fa9c1a;
}
.navbar-default .navbar-nav > .active > a,
.navbar-default .navbar-nav > .active > a:hover,
.navbar-default .navbar-nav > .active > a:focus {
  color: #ffffff;
  background-color: #fa9c1a;
}
.navbar-default .navbar-nav > .open > a,
.navbar-default .navbar-nav > .open > a:hover,
.navbar-default .navbar-nav > .open > a:focus {
  color: #ffffff;
  background-color: #fa9c1a;
}
.navbar-default .navbar-toggle {
  border-color: #fa9c1a;
}
.navbar-default .navbar-toggle:hover,
.navbar-default .navbar-toggle:focus {
  background-color: #fa9c1a;
}
.navbar-default .navbar-toggle .icon-bar {
  background-color: #58595b;
}
.navbar-default .navbar-collapse,
.navbar-default .navbar-form {
  border-color: #58595b;
}
.navbar-default .navbar-link {
  color: #58595b;
}
.navbar-default .navbar-link:hover {
  color: #ffffff;
}

@media (max-width: 767px) {
  .navbar-default .navbar-nav .open .dropdown-menu > li > a {
    color: #58595b;
  }
  .navbar-default .navbar-nav .open .dropdown-menu > li > a:hover,
  .navbar-default .navbar-nav .open .dropdown-menu > li > a:focus {
    color: #ffffff;
  }
  .navbar-default .navbar-nav .open .dropdown-menu > .active > a,
  .navbar-default .navbar-nav .open .dropdown-menu > .active > a:hover,
  .navbar-default .navbar-nav .open .dropdown-menu > .active > a:focus {
    color: #ffffff;
    background-color: #fa9c1a;
  }
}

.risk_model_none
{background-color: #00AAFF; padding:5px;}
.risk_model_low
{background-color: #ffd800; padding:5px;}
.risk_model_medium
{background-color: #ff6a00; padding:5px;}
.risk_model_high
{background-color: #f12828; padding:5px;}
.modal-header{background-color: #FA9C1A;}
.modal-header h4 {color: #fff;}
/* no transition to be used in the carto mode */
.progress .progress-bar{
    -webkit-transition: none;
    -o-transition: none;
    transition: none;
}
</style>";
        }

        protected void GenerateSection(string title, GenerateContentDelegate generateContent)
        {
            string id = "section" + title.Replace(" ", "");
            Add(@"
<!-- Section " + title + @" -->
<div id=""" + id + @""">
    <div class=""row"">
		<div class=""starter-template"">
			<div class=""panel panel-default"">
				<div class=""panel-heading panel-cp"">
					<h1 class=""panel-title""><a data-toggle=""collapse"" href=""#panel" + id + @""">" + title + @"</a></h1>
				</div>
				<div class=""panel-body collapse in"" id=""panel" + id + @""">
");
            generateContent();
            Add(@"
				</div>
			</div>
		</div>
	</div>
</div>
<!-- Section " + title + @" end -->
");
        }

        protected void GenerateSubSection(string title)
        {
            Add(@"
		<!-- SubSection " + title + @" -->
		<div class=""row""><div class=""col-lg-12"">
			<h2>" + title + @"</h2>
		</div></div>
        <!-- SubSection " + title + @" end -->");
        }

        protected void GenerateAccordion(string accordion, GenerateContentDelegate content)
        {
            Add(@"
		<!-- Accordion " + accordion + @" -->
		<div class=""row"">
			<div class=""col-md-12"">
				<div class=""panel-group"" id=""" + accordion + @""">
");
            content();
            Add(@"
				</div>
			</div>
		</div>
		<!-- Accordion " + accordion + @" end -->
");
        }


        // see https://msdn.microsoft.com/en-us/library/cc223741.aspx
        // 6.1.4.2 msDS-Behavior-Version: DC Functional Level
        public static string DecodeDomainFunctionalLevel(int DomainFunctionalLevel)
        {
            switch (DomainFunctionalLevel)
            {
                case 0:
                    return "Windows 2000";
                case 1:
                    return "Windows Server 2003 interim";
                case 2:
                    return "Windows Server 2003";
                case 3:
                    return "Windows Server 2008";
                case 4:
                    return "Windows Server 2008 R2";
                case 5:
                    return "Windows Server 2012";
                case 6:
                    return "Windows Server 2012 R2";
                case 7:
                    return "Windows Server 2016";
                default:
                    return "Unknown: " + DomainFunctionalLevel;
            }
        }

        // see https://msdn.microsoft.com/en-us/library/cc223743.aspx
        // 6.1.4.4 msDS-Behavior-Version: Forest Functional Level
        public static string DecodeForestFunctionalLevel(int ForestFunctionalLevel)
        {
            switch (ForestFunctionalLevel)
            {
                case 0:
                    return "Windows 2000";
                case 1:
                    return "Windows Server 2003 mixed";
                case 2:
                    return "Windows Server 2003";
                case 3:
                    return "Windows Server 2008";
                case 4:
                    return "Windows Server 2008 R2";
                case 5:
                    return "Windows Server 2012";
                case 6:
                    return "Windows Server 2012 R2";
                case 7:
                    return "Windows Server 2016";
                default:
                    return "Unknown: " + ForestFunctionalLevel;
            }
        }

        protected int OrderOS(string os1, string os2)
        {
            int ios1 = OSToInt(os1);
            int ios2 = OSToInt(os2);
            if (ios1 > 0 && ios2 > 0)
            {
                if (ios1 > ios2)
                    return 1;
                else if (ios1 < ios2)
                    return -1;
                return 0;
            }
            else if (ios1 > 0)
                return -1;
            else if (ios2 > 0)
                return 1;
            return String.Compare(os1, os2);
        }

        protected int OSToInt(string os)
        {
            switch (os)
            {
                case "Windows XP":
                    return 1;
                case "Windows Vista":
                    return 2;
                case "Windows 7":
                    return 3;
                case "Windows 8":
                    return 4;
                case "Windows 10":
                    return 5;
                case "Windows NT":
                    return 6;
                case "Windows 2000":
                    return 7;
                case "Windows 2003":
                    return 8;
                case "Windows 2008":
                    return 9;
                case "Windows 2012":
                    return 10;
                case "Windows 2016":
                    return 11;
                case "Windows Embedded":
                    return 12;
                case "OperatingSystem not set":
                    return 13;
            }
            return 0;
        }

        protected string GetPSOStringValue(GPPSecurityPolicy policy, string propertyName)
        {
            foreach (var property in policy.Properties)
            {
                if (property.Property == propertyName)
                {
                    if (property.Value == 0)
                    {
                        if (propertyName == "PasswordComplexity")
                        {
                            return "<span class=\"unticked\">False</span>";
                        }
                        if (propertyName == "ClearTextPassword"
                            || propertyName == "ScreenSaveActive" || propertyName == "ScreenSaverIsSecure")
                            return "False";

                    }
                    if (property.Value == -1 && propertyName == "MaximumPasswordAge")
                    {
                        return "<span class=\"unticked\">Never expires</span>";
                    }
                    if (property.Value == 1)
                    {
                        if (propertyName == "ClearTextPassword")
                            return "<span class=\"unticked\">True</span>";
                        if (propertyName == "PasswordComplexity"
                            || propertyName == "ScreenSaveActive" || propertyName == "ScreenSaverIsSecure")
                            return "True";
                    }
                    if (propertyName == "MinimumPasswordLength")
                    {
                        if (property.Value < 8)
                        {
                            return "<span class=\"unticked\">" + property.Value.ToString() + "</span>";
                        }
                    }
                    if (propertyName == "MinimumPasswordAge")
                    {
                        if (property.Value == 0)
                        {
                            return "<span class=\"unticked\">0 day</span>";
                        }
                        return property.Value.ToString() + " day(s)";
                    }
                    if (propertyName == "MaximumPasswordAge")
                    {
                        return property.Value.ToString() + " day(s)";
                    }
                    if (propertyName == "ResetLockoutCount" || propertyName == "LockoutDuration")
                    {
						if (property.Value <= 0)
							return "Infinite";
                        return property.Value.ToString() + " minute(s)";
                    }
                    return property.Value.ToString();
                }
            }
            return "Not Set";
        }

        protected string GetLinkForLsaSetting(string property)
        {
            switch (property.ToLowerInvariant())
            {
                case "enableguestaccount":
                    return @"<a href=""https://msdn.microsoft.com/en-us/library/hh128296.aspx"">EnableGuestAccount</a>";
                case "lsaanonymousnamelookup":
                    return @"<a href=""https://msdn.microsoft.com/en-us/library/hh128296.aspx"">LSAAnonymousNameLookup</a>";
                case "everyoneincludesanonymous":
                    return @"<a href=""https://support.microsoft.com/en-us/kb/278259"">EveryoneIncludesAnonymous</a>";
                case "limitblankpassworduse":
                    return @"<a href=""https://technet.microsoft.com/en-us/library/jj852174.aspx"">LimitBlankPasswordUse</a>";
                case "forceguest":
                    return @"<a href=""https://technet.microsoft.com/en-us/library/jj852219%28v=ws.11%29.aspx"">ForceGuest</a>";
                case "lmcompatibilitylevel":
                    return @"<a href=""https://technet.microsoft.com/en-us/library/cc960646.aspx"">LmCompatibilityLevel</a>";
                case "NoLMHash":
                    return @"<a href=""https://technet.microsoft.com/en-us/library/cc736342%28v=ws.10%29.aspx"">NoLMHash</a>";
                case "restrictanonymous":
                    return @"<a href=""https://technet.microsoft.com/en-us/library/cc963223.aspx"">RestrictAnonymous</a>";
                case "restrictanonymoussam":
                    return @"<a href=""https://technet.microsoft.com/en-us/library/jj852184.aspx"">RestrictAnonymousSam</a>";

            }
            return property;
        }

        protected string GetEnumDescription(HealthcheckRiskModelCategory value)
        {
            // Get the Description attribute value for the enum value
            FieldInfo fi = value.GetType().GetField(value.ToString());
            DescriptionAttribute[] attributes =
                (DescriptionAttribute[])fi.GetCustomAttributes(
                    typeof(DescriptionAttribute), false);

            if (attributes.Length > 0)
            {
                return attributes[0].Description;
            }
            else
            {
                return value.ToString();
            }
        }

        protected void GenerateGauge(int percentage)
        {
            Add(@"<svg viewBox=""0 0 400 230"" ><g transform=""translate(190, 190)""><path class=""arc chart-first"" d=""M-170,2.0818995585505004e-14A170,170 0 0,1 -120.20815280171311,-120.20815280171307L-86.26702730475881,-86.26702730475878A122,122 0 0,0 -122,1.494069094959771e-14Z""></path><path class=""arc chart-second"" d=""M-117.165698922674,-123.17548049819537A170,170 0 0,1 -3.122849337825751e-14,-170L-2.2411036424396564e-14,-122A122,122 0 0,0 -84.08361922686016,-88.39652129870491Z""></path><path class=""arc chart-third"" d=""M4.249557305501125,-169.94687776686945A170,170 0 0,1 120.20815280171306,-120.20815280171311L86.26702730475877,-86.26702730475881A122,122 0 0,0 3.0496823015949253,-121.96187698563573Z""></path><path class=""arc chart-quart"" d=""M123.17548049819526,-117.16569892267411A170,170 0 0,1 170,-1.9262832252003132e-13L122,-1.382391491026107e-13A122,122 0 0,0 88.39652129870484,-84.08361922686025Z""></path><circle class=""needle-center"" cx=""0"" cy=""0"" r=""18""></circle><path class=""needle"" d=""");
            GenerateChartNeedle(percentage);
            Add(@"""></path></g><text transform=""translate(3.8, 190)"" font-size=""15"">0</text><text transform=""translate(176.74418604651163, 12.666666666666666)"" font-size=""15"">50</text><text transform=""translate(368.93203883495147, 190)"" font-size=""15"">100</text></svg>");
        }

        protected void GenerateChartNeedle(int percentage)
        {
            double leftX, leftY, rightX, rightY, thetaRad, topX, topY;
            NumberFormatInfo nfi = new NumberFormatInfo();
            nfi.NumberDecimalSeparator = ".";
            thetaRad = percentage * Math.PI / 100;
            topX = -144 * Math.Cos(thetaRad);
            topY = -144 * Math.Sin(thetaRad);
            leftX = -18 * Math.Cos(thetaRad - Math.PI / 2);
            leftY = -18 * Math.Sin(thetaRad - Math.PI / 2);
            rightX = -18 * Math.Cos(thetaRad + Math.PI / 2);
            rightY = -18 * Math.Sin(thetaRad + Math.PI / 2);
            Add("M ");
            Add(leftX.ToString(nfi));
            Add(" ");
            Add(leftY.ToString(nfi));
            Add(" L ");
            Add(topX.ToString(nfi));
            Add(" ");
            Add(topY.ToString(nfi));
            Add(" L ");
            Add(rightX.ToString(nfi));
            Add(" ");
            Add(rightY.ToString(nfi));
        }

        protected string Encode(string stringToencode)
        {
            // could have use HttpUtility.HtmlEncode but not dotnet core compliant
            if (string.IsNullOrEmpty(stringToencode)) return stringToencode;

            string returnString = stringToencode;

            returnString = returnString.Replace("&", "&amp;");
            returnString = returnString.Replace("'", "&apos;");
            returnString = returnString.Replace("\"", "&quot;");
            returnString = returnString.Replace(">", "&gt;");
            returnString = returnString.Replace("<", "&lt;");

            return returnString;
        }

        protected string PrintDomain(DomainKey key)
        {
            string label = key.DomainName;
            if (GetUrlCallback == null)
                return label;
            string htmlData = GetUrlCallback(key, label);
            if (String.IsNullOrEmpty(htmlData))
                return label;
            return htmlData;
        }
    }
}
