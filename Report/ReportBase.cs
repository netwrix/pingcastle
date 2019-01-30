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
using PingCastle.Rules;
using PingCastle.Healthcheck;
using PingCastle.Data;
using System.Text.RegularExpressions;

namespace PingCastle.Report
{
    public abstract class ReportBase
    {

        protected StringBuilder sb = new StringBuilder();
        public delegate bool HasDomainAmbigousNameDelegate(DomainKey domainKey);

		protected GetUrlDelegate GetUrlCallback;

        public HasDomainAmbigousNameDelegate HasDomainAmbigousName { get; set; }

		public void SetUrlDisplayDelegate(GetUrlDelegate uRLDelegate)
		{
			GetUrlCallback = uRLDelegate;
		}

        public string GenerateReportFile(string filename)
        {
            var reportSB = new StringBuilder(TemplateManager.LoadResponsiveTemplate());

			Hook(reportSB);

			sb.Length = 0;
			GenerateTitleInformation();
			reportSB = reportSB.Replace("<%=Title%>", sb.ToString());

			sb.Length = 0;
			GenerateBaseHeaderInformation();
			GenerateHeaderInformation();
			reportSB = reportSB.Replace("<%=Header%>", sb.ToString());

			sb.Length = 0;
			GenerateBodyInformation();
			reportSB = reportSB.Replace("<%=Body%>", sb.ToString());

			sb.Length = 0;
			GenerateBaseFooterInformation();
			GenerateFooterInformation();
			reportSB = reportSB.Replace("<%=Footer%>", sb.ToString());

			var html = reportSB.ToString();
            File.WriteAllText(filename, html);
            return html;
        }

		private void GenerateBaseHeaderInformation()
		{
			Add(@"<style>");
			Add(TemplateManager.LoadBootstrapCss());
			Add(@"</style>");
		}

		private void GenerateBaseFooterInformation()
		{
			Add(@"<script>");
			Add(TemplateManager.LoadJqueryJs());
			Add(TemplateManager.LoadPopperJs());
			Add(TemplateManager.LoadBootstrapJs());
			Add(@"</script>");
		}

		protected virtual void Hook(StringBuilder sbHtml)
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

		protected void AddEncoded(string text)
		{
			sb.Append(ReportHelper.Encode(text));
		}

		protected void Add(DateTime date)
        {
            sb.Append(date.ToString("u"));
        }

        protected delegate void GenerateContentDelegate();

        protected abstract void GenerateFooterInformation();

		protected abstract void GenerateTitleInformation();

		protected abstract void GenerateHeaderInformation();

		protected abstract void GenerateBodyInformation();

        public static string GetStyleSheetTheme()
        {
            return @"
<!-- Custom styles for this template -->
<style type=""text/css"">

body { 
	background:#e1e1e1;
	padding-top: 50px;
	margin-top: 10px;
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

.ticked { color: #4CAF50;}

.unticked { color: #FF1744;}

a {
	color: #fa9c1a;
}

a:hover {
	color: #58595b;
}

.navbar-custom {
	background-color: #ffffff;
}

.navbar-custom .navbar-toggler-icon {
	background-image: url(""data:image/svg+xml;charset=utf8,%3Csvg viewBox='0 0 30 30' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath stroke='rgba(0, 0, 0, 0.5)' stroke-width='2' stroke-linecap='round' stroke-miterlimit='10' d='M4 7h22M4 15h22M4 23h22'/%3E%3C/svg%3E"");
}
.navbar-custom .navbar-toggler {
	color: rgba(0, 0, 0, 0.5);
	border-color: rgba(0, 0, 0, 0.1);
}

/* change the brand and text color */
.navbar-custom .navbar-brand, .navbar-custom .navbar-text {
	color: #fa9c1a;
}
/* change the link color */
.navbar-custom .navbar-nav .nav-link {
	color: #58595b;
}

.navbar-custom .navbar-nav > .active > a,
.navbar-custom .navbar-nav > .active > a:hover,
.navbar-custom .navbar-nav > .active > a:focus {
	color: #fff;
	background-color: #fa9c1a;
}

.nav-tabs .nav-link {
	border-color: #e9ecef #e9ecef #dee2e6;
	color: #58595b;
}

.nav-tabs .nav-link.disabled {
	color: #6c757d;
	background-color: transparent;
	border-color: transparent;
}

.nav-tabs .nav-link.active,
.nav-tabs .nav-item.show .nav-link {
	color: #fff;
	background-color: #fa9c1a;
	border-color: #dee2e6 #dee2e6 #fff;
}

/* navbar */
.navbar-brand {
	margin: 0;
	padding: 0;
}

.navbar-brand img {
	max-height: 100%;
}
	
.dropdown-item.active, .dropdown-item:active {
	background-color: #fa9c1a;
}

.border-bottom {
	border-bottom-color: #fa9c1a !important;
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
.info-mark {
	background-color: #fff;
	border-radius: 50%;
	border: 1px solid #58595b;
	color: #58595b;
	display: inline-block;
	font-size: 16px;
	height: 20px;
	text-align: center;
	vertical-align: middle;
	width: 20px;
	font-style: normal;
}
.num
{
	text-align: right !important;
}
a[name] {
  padding-top: 60px;
  margin-top: -60px;
  display: inline-block; /* required for webkit browsers */
}
</style>
<link href=""data:image/x-icon;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAE10lEQVRYw71XfWwTdRhet4xBssFigMja61rafbK5bGFuiqh1ISaMP2QI++jaXtvUZGKIigUkUTTzmwUxIQtRYBZHr3e9rjYOY4zLlprMEDROJagZAzEgMYiTZJvr7zrmc0cHXekXxfWSJ9f2rvc8977P+76/X0YGDsKubiSuwh2ELy8SfPVZGek+QG4hTjkhDPUrPh8grOYJwhXlCV9tSZMAdnUDBEwRZ8HsTcivE0bxJQR1QEyJ0L8+e2EFcEWlhJFfuS3gFoIQcpG4VMcRmUbcd58wqJeJ/2FYfhGwDegG9gKrUhfAly4H0UgUAWGQTyAiw8Sl3kv6qpaDcDMwDswCQaCH5fqWpCRA8D2YQ1zK/vgCQnCprgv9j9aD8FCIfA4XAGVqAj7fIBrxg6QEMIop4i7ZADI7IIQJ8AP5qaeBobYnJ0D5O6LwsIvzrADhQWAUGHJxfEOA1TwE09LEU6EUPnsk8y4rQfO0VIqxyW+IHgh4KnVWs6HaaDI/85J9t+Z4r1Pl599ZSbjiRlz/Ec8QcD4rRdRdrCOcNlcYaE6mErS1qITxGAYkeKDzam9VsdlibWptaz8DCPp2488Wq20H8daUg/TCndGS/wN8IUWXK9YSvix2k4NaCvkdi0I+DvJ9gwcbKIOR3gXiqy2t+tk5QITvoqNODZLRONELSs9mqI/wohshJl8YbJPNF+BZk4sb/BGGOw/y1lefb1WD6DDIp8LJQwK+P9bZrIQ3hpLykFTOiq/x3F1o/QW3K+GkLhPqGgir3omS9OOmoQCrXW+hjTVtesMAyIKR5CJw7fL2DlsZxDuSEyAhAAE9SIk8I9TVZHC1Fmc9zrpL7k3yPx1rCvTthkYx39GI54Drk7TZCrNp3k2uiqSUvoJSXnbr7UG6FuQjoY4mdrcXOp59biXe7nQ88hBm4A0TBJgR3pkE5KOYO83EW50zL/8gfDuiq/105NjHFPL7aRICZlGSL2NOPCblNzr5jJhSvHmtwFfI7qgAEL4ZIWDkaI8DKTAyILiRSEC7weSYYCtLQHI5Cvk0DNoDbxXic/QSBGEF8A0wDVwBbKc+sS2maVpsOJ1IxQiIpmMJgFC//9CTqATFdxGO/xu/7YG5l8VtQvCAKKKAdfdtQkutHufqNchVN1S/9i+jrurc2aI0muitIDoBwkuRUYHAM512Won7D4DwN8kLDDWGkG8F+aK7XB2pWvCAb6W8ie3XiXUCo2Dxu/7c0ZpCq9n0AEJuB+mwWAHAWXx/an/X+3l+91v3T/Loii7Vi3B5vdD/eGYKqyP1nhhGQi4VPyAyXeLQ+XBfE2WizRtNtEWsoHWAFzgNvM5xHDqdPuXl2ZbEQ0l+DSE+Cedv7uOZfJAOhBk4AFjuZX24VjJPUouTQqfXfUIFwvMRVdR1L+tDcSidS66rUcNjfNsqELrDyCdg6m2pC3CX5krDIvFQgSeobuKpXIq1YBmI3wN6ARoClqQsQPDVZUFAbwLyvzCwdmOEL537H0pYxvHeLAj4XzYq++P0c2xeVE2o7+wF3KiobaE+ENHPqUFcq8Ucly3wVk2lQ5gn5/UAp/ywaNDgKXsatmpckThY/gitiq5J+Xap8tK3WeXLb+6UGMUvWC03EV9ddkY6D2y9cpDrN9CU1kHAgub7P7CsZhuj7eUMAAAAAElFTkSuQmCC"" rel=""icon"" type=""image/x-icon"" />
";
        }

		protected void GenerateNavigation(string title, string domain, DateTime generationDate)
		{
			Add(@"
<nav class=""navbar py-0 navbar-expand-lg navbar-custom fixed-top border-bottom"">
	<div class=""container"">
		<a href=""#"" class=""navbar-brand"">
			<img src=""data:image/png;base64,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"" />
		</a>
		<button class=""navbar-toggler"" type=""button"" data-toggle=""collapse"" data-target=""#navbarToggler"" aria-controls=""navbarToggler"" aria-expanded=""false"" aria-label=""Toggle navigation"">
			<span class=""navbar-toggler-icon""></span>
		</button>

		<div class=""collapse navbar-collapse"" id=""navbarToggler"">
			<ul class=""navbar-nav mr-auto"">
				<li class=""nav-item active"">
					<a class=""nav-link p-3"" href=""#"" role=""button"">
");
			if (String.IsNullOrEmpty(domain))
				Add(title);
			else
				Add(domain);
			Add(@"
					</a>
				</li>
				<li class=""nav-item"">
					<a class=""nav-link p-3"" href=""#"" role=""button"">
");
			Add(generationDate.ToString("yyyy-MM-dd"));
				Add(@"
					</a>
				</li>
				<li class=""nav-item"">
					<a class=""nav-link p-3"" role=""button"" href=""#modalAbout"" data-toggle=""modal"">About</a>
				</li>
			</ul>
		</div>
	</div>
</nav>
");
		}

		protected void GenerateAbout(string aboutString)
		{
			Add(@"
<!-- Modal -->
<div class=""modal"" id=""modalAbout"" role=""dialog"">
    <div class=""modal-dialog modal-lg"">
        <!-- Modal content-->
        <div class=""modal-content"">
            <div class=""modal-header"">
                <h4 class=""modal-title"">About</h4>
                <button type=""button"" class=""close"" data-dismiss=""modal"" aria-label=""Close"">
                    <span aria-hidden=""true"">&times;</span>
                </button>
            </div>
            <div class=""modal-body"">
                <div class=""row"">
                     <div class=""col-lg-12"">
");
			Add(aboutString);
			Add(@"
                     </div>
                </div>
            </div>
            <div class=""modal-footer"">
                <button type=""button"" class=""btn btn-secondary"" data-dismiss=""modal"">Close</button>
            </div>
        </div>

    </div>
</div>
");
		}

        protected void GenerateSection(string title, GenerateContentDelegate generateContent)
        {
            string id = "section" + title.Replace(" ", "");
            Add(@"
<!-- Section " + title + @" -->
<div id=""" + id + @""">
	<div class=""row"">
		<div class=""col-lg-12"">
			<div class=""starter-template"">
				<div class=""card mb-4"">
					<div class=""card-header"">
						<h1 class=""card-title""><a data-toggle=""collapse"" aria-expanded=""true"" href=""#panel" + id + @""">" + title + @"</a></h1>
					</div>
					<div class=""card-body collapse show"" id=""panel" + id + @""">
");
            generateContent();
            Add(@"
					</div>
				</div>
			</div>
		</div>
	</div>
</div>
<!-- Section " + title + @" end -->
");
        }

        protected void GenerateSubSection(string title, string section = null)
        {
			Add(@"
		<!-- SubSection ");
			AddEncoded(title);
			Add(@" -->");
			if (!string.IsNullOrEmpty(section))
			{
				Add(@"
		<a name=""");
				AddEncoded(section);
				Add(@"""></a>
");
			}
			Add(@"
		<div class=""row""><div class=""col-lg-12 mt-2"">
			<h2>");
			AddEncoded(title);
			Add(@"</h2>
		</div></div>
        <!-- SubSection ");
			AddEncoded(title);
			Add(@" end -->");
        }

        protected void GenerateAccordion(string accordion, GenerateContentDelegate content)
        {
			Add(@"
		<!-- Accordion ");
			AddEncoded(accordion);
			Add(@" -->
<div id=""");
			Add(accordion);
			Add(@""">
<div class=""card"">
    ");
			content();
  Add(@"</div></div>
			<!-- Accordion ");
			Add(accordion);
			Add(@" end -->
");

        }
		protected void GenerateAccordionDetail(string id, string dataParent, string title, int? itemCount, bool RuleStyle, GenerateContentDelegate content)
		{
			Add(@"
    <div class=""card-header"" id=""heading");
			Add(id);
			Add(@""">
      <span class=""card-title mb-0"">
        <button class=""btn btn-link"" data-toggle=""collapse"" data-target=""#");
			Add(id);
			Add(@""" aria-expanded=""false"" aria-controls=""");
			Add(id);
			Add(@""">
          ");
			Add(title);
			Add(@"
        </button>
      </span>
");
			if (itemCount != null)
			{
				if (!RuleStyle)
				{
					Add(@"<i class=""float-right"">[");
					Add((int)itemCount);
					Add(@"]</i>");
				}
				else
				{
					Add(@"<i class=""float-right"">+ ");
					Add((int)itemCount);
					Add(@" Point(s)</i>");
				}
			}
			Add(@"
    </div>

    <div id=""");
			Add(id);
			Add(@""" class=""collapse"" aria-labelledby=""heading");
			Add(id);
			Add(@""" data-parent=""#");
			Add(dataParent);
			Add(@""">
      <div class=""card-body"">
        ");
			content();
			Add(@"
    </div>
  </div>");
		}

		private static string GenerateId(string title)
		{
			return "section" + title.Replace(" ", "");
		}

		protected void GenerateTabHeader(string title, string selectedTab, bool defaultIfTabEmpty = false)
		{
			string id = GenerateId(title);
			bool isActive = (String.IsNullOrEmpty(selectedTab) ? defaultIfTabEmpty : selectedTab == id);
			Add(@"<li class=""nav-item""><a href=""#");
			Add(id);
			Add(@""" class=""nav-link ");
			if (isActive)
				Add(@"active");
			Add(@""" role=""tab"" data-toggle=""tab"">");
			Add(title);
			Add("</a></li>");
		}

		protected void GenerateSectionFluid(string title, GenerateContentDelegate generateContent, string selectedTab, bool defaultIfTabEmpty = false)
		{
			string id = GenerateId(title);
			bool isActive = (String.IsNullOrEmpty(selectedTab) ? defaultIfTabEmpty : selectedTab == id);
			Add(@"
<!-- Section ");
			Add(title);
			Add(@" -->
<div class=""tab-pane");
			if (isActive)
				Add(" active");
			Add(@""" id=""");
			Add(id);
			Add(@""">
<div class=""row""><div class=""col-lg-12"">
	<div class=""starter-template"">
		<div class=""row""><div class=""col-lg-12"">
			<h1>");
			Add(title);
			Add(@"</h1>
		</div></div>
");
			generateContent();
			Add(@"
			</div>
		</div>
	</div>
</div>
<!-- Section " + title + @" end -->
");
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

		// this function is used to sort operating system based not on name but on its order
		// the value returned doesn't have a meaning at all. It is used for a comparison & sort
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
				case "Windows 2019":
					return 12;
                case "Windows Embedded":
                    return 13;
                case "OperatingSystem not set":
                    return 14;
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

		protected string PrintDomain(DomainKey key)
		{
			string label = key.DomainName;
			if (String.IsNullOrEmpty(label))
			{
				if (!String.IsNullOrEmpty(key.DomainNetBIOS))
					label = key.DomainNetBIOS;
				else
					label = key.DomainSID;
			}
            if (GetUrlCallback == null)
                return label;
            string htmlData = GetUrlCallback(key, label);
            if (String.IsNullOrEmpty(htmlData))
                return label;
            return htmlData;
        }

		protected string NewLineToBR(string data)
		{
			if (String.IsNullOrEmpty(data))
				return data;
			return data.Replace("\r\n", "<br>\r\n");
		}

	}
}
