//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Data;
using PingCastle.Healthcheck;
using PingCastle.template;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;

namespace PingCastle.Report
{
    public abstract class ReportBase
    {

        protected StringBuilder sb = new StringBuilder();
        public delegate bool HasDomainAmbigousNameDelegate(DomainKey domainKey);
        protected string ReportID;
        protected string PingCastleEnterpriseBaseUrl = "https://www.pingcastle.com/reports/";

        protected GetUrlDelegateDomain GetUrlCallbackDomain;
        protected GetUrlDelegateAzureAD GetUrlCallbackAzureAD;
        protected GetAdditionInfoDelegate AdditionInfoDelegate;
        protected AddHtmlToTabSection TabDelegate;

        public HasDomainAmbigousNameDelegate HasDomainAmbigousName { get; set; }

        public static bool NoCspHeader { get; set; }

        public void SetUrlDisplayDelegate(GetUrlDelegateDomain uRLDelegate)
        {
            GetUrlCallbackDomain = uRLDelegate;
        }

        public void SetUrlDisplayDelegate(GetUrlDelegateAzureAD uRLDelegate)
        {
            GetUrlCallbackAzureAD = uRLDelegate;
        }

        public void SetAdditionalInfoDelegate(GetAdditionInfoDelegate additionInfoDelegate)
        {
            AdditionInfoDelegate = additionInfoDelegate;
        }

        public void SetHtmlToTabSectionDelegate(AddHtmlToTabSection tabDelegate)
        {
            TabDelegate = tabDelegate;
        }

        private List<string> CSSToAdd = new List<string> { 
            TemplateManager.LoadBootstrapCss(),
            TemplateManager.LoadBootstrapTableCss(),
            TemplateManager.LoadReportBaseCss(),
        };

        private List<string> JSToAdd = new List<string> { 
            TemplateManager.LoadJqueryJs(), 
            TemplateManager.LoadPopperJs(), 
            TemplateManager.LoadBootstrapJs(),
            TemplateManager.LoadBootstrapTableJs(),
            TemplateManager.LoadReportBaseJs(),
        };

        public string GenerateReportFile(string filename)
        {
            ReferenceJSAndCSS();

            var reportSB = new StringBuilder(TemplateManager.LoadResponsiveTemplate());

            Hook(reportSB);

            sb.Length = 0;

            sb.Length = 0;
            GenerateCspMeta();
            AddLine();
            Add("<title>");
            GenerateTitleInformation();
            Add("</title>");
            /*Add("<base href=\"");
            Add(PingCastleEnterpriseBaseUrl);
            if (!string.IsNullOrEmpty(ReportID))
            {
                AddEncoded(ReportID);
                Add("/");
            }
            Add("\">");*/
            Add(favicon);
            GenerateCss();
            reportSB = reportSB.Replace("<%=Header%>", sb.ToString());

            sb.Length = 0;
            GenerateBodyInformation();
            reportSB = reportSB.Replace("<%=Body%>", sb.ToString());

            sb.Length = 0;
            GenerateFooterInformation();
            GenerateJavascript();
            reportSB = reportSB.Replace("<%=Footer%>", sb.ToString());

            var html = reportSB.ToString();
            if (!String.IsNullOrEmpty(filename))
            {
                File.WriteAllText(filename, html);
            }
            return html;
        }

        private void GenerateJavascript()
        {
            foreach (var script in JSToAdd)
            {
                AddLine(@"<script type=""text/javascript"">");
                AddLine(script);
                AddLine("</script>");
            }
        }

        private void GenerateCss()
        {
            foreach (var css in CSSToAdd)
            {
                AddLine(@"<style type=""text/css"">");
                AddLine(css);
                AddLine("</style>");
            }
        }

        private void GenerateCspMeta()
        {
            if (NoCspHeader)
                return;
            Add(@"<meta http-equiv=""Content-Security-Policy"" content=""default-src 'self'; script-src ");
            foreach (var script in JSToAdd)
            {
                ComputeCSPHash(script);
            }
            Add(@" 'unsafe-inline'; style-src ");
            foreach (var css in CSSToAdd)
            {
                ComputeCSPHash(css);
            }
            Add(@" 'unsafe-inline'; object-src 'none'; base-uri https://www.pingcastle.com ; img-src data: https://www.pingcastle.com;""/>");
        }

        private void ComputeCSPHash(string css)
        {
            using (var sha256Hash = SHA256.Create())
            {
                byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes("\n" + css.Replace("\r", "") + "\n"));
                Add("'sha256-");
                Add(Convert.ToBase64String(bytes));
                Add("' ");
            }
        }

        protected void AddStyle(string style)
        {
            if (!CSSToAdd.Contains(style))
                CSSToAdd.Add(style);
        }

        protected void AddScript(string script)
        {
            if (!JSToAdd.Contains(script))
                JSToAdd.Add(script);
        }


        protected virtual void Hook(StringBuilder sbHtml)
        {

        }

        protected void AddLink(string link)
        {
            sb.Append("<a href=\"");
            sb.Append(link);
            sb.Append("\">");
            sb.Append(link);
            sb.Append("</a>");
        }

        protected void AddListStart()
        {
            Add(@"<ul><li>");
        }

        protected void AddListContinue()
        {
            Add(@"</li><li>");
        }

        protected void AddListEnd()
        {
            Add(@"</li></ul>");
        }

        protected void AddLine(string text)
        {
            sb.AppendLine(text);
        }

        protected void AddLine()
        {
            sb.AppendLine();
        }

        protected void Add(int value)
        {
            sb.Append(value);
        }

        protected void Add(ulong value)
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

        protected void AddJsonEncoded(string text)
        {
            sb.Append(ReportHelper.EscapeJsonString(text));
        }

        protected void Add(DateTime date)
        {
            sb.Append(date.ToString("u"));
        }
        protected void DescribeBegin()
        {
            Add(@"<dl class='row'>");
        }

        protected void DescribeLabel(string label, string id = null)
        {
            Add(@"<dt class='col-sm-3'");
            if (!string.IsNullOrEmpty(id))
            {
                Add(" id='label_");
                Add(id);
                Add("'");
            }
            Add(">");
            AddEncoded(label);
            Add("</dt>");
        }

        protected void DescribeValue(string value, string id)
        {
            Add(@"<dd class='col-sm-9'");
            if (!string.IsNullOrEmpty(id))
            {
                Add(" id='label_");
                Add(id);
                Add("'");
            }
            Add(">");
            AddEncoded(value);
            Add("</dd>");
        }

        protected void DescribeEnd()
        {
            Add(@"</dl>");
        }


        protected void AddAnchor(string label)
        {
            Add(@"<a name=""");
            Add(label);
            Add(@"""></a>");
        }

        protected void AddParagraph(string content)
        {
            Add("<div class='row'><div class='col-lg-12'><p>");
            Add(content);
            Add("</p></div></div>");
        }

        protected void AddBeginTable(string ariaLabel, bool SimpleTable = false, string id = null)
        {
            Add(@"
		<div class=""row"">
			<div class=""col-md-12 table-responsive"">
				<table class=""table table-striped table-bordered");
            if (SimpleTable)
            {
                Add(" nopaging");
            }
            else
            {
                Add(@""" data-toggle=""table"" data-pagination=""true"" data-search=""true"" data-show-export=""true"" data-page-list=""[10,25,50,100,200,All]""");
            }
            if (!string.IsNullOrEmpty(id))
            {
                Add(" id=\"");
                AddEncoded(id);
                Add("\"");
            }
            if (!string.IsNullOrEmpty(ariaLabel))
            {
                Add(" aria-label=\"");
                AddEncoded(ariaLabel);
                Add("\"");
            }
            Add(@">
					<thead>
					<tr>");
        }

        protected void AddBeginTableData()
        {
            Add(@"</tr>
					</thead>
					<tbody>");
        }

        private bool footerMode = false;
        protected void AddEndTable(GenerateContentDelegate footer = null)
        {
            Add(@"</tbody>");
            if (footer != null)
            {
                Add("<tfoot>");
                AddBeginRow();
                footerMode = true;
                footer();
                footerMode = false;
                AddEndRow();
                Add("</tfoot>");
            }
            else
            {
                Add("<tfoot></tfoot>");
            }
            Add(@"
				</table>
			</div>
		</div>
");
        }

        protected void AddBeginRow()
        {
            Add(@"<tr>");
        }

        protected void AddEndRow()
        {
            Add(@"</tr>");
        }

        protected void AddBeginTooltip(bool wide = false, bool html = false)
        {
            Add(@"&nbsp;<i class=""info-mark d-print-none has-tooltip"" data-bs-placement=""bottom"" data1-bs-toggle=""tooltip""");
            if (wide)
            {
                Add(@" data-bs-template=""<div class='tooltip' role='tooltip'><div class='tooltip-arrow'></div><div class='tooltip-inner tooltip-wide'></div></div>"" ");
            }
            if (html)
            {
                Add(@" data-bs-html=""true"" ");
            }
            Add(@" title="""" data-bs-original-title=""");
        }

        protected void AddEndTooltip()
        {
            Add(@""">?</i>");
        }

        protected void AddHeaderText(string text, string tooltip, bool widetooltip, bool html = false)
        {
            AddHeaderText(text, tooltip, 0, 0, widetooltip, html);
        }

        protected void AddHeaderText(string text,
            string tooltip = null,
            int rowspan = 0,
            int colspan = 0,
            bool widetooltip = false,
            bool html = false,
            string datafield = null,
            string dataformatter = null
            )
        {
            Add(@"<th  data-sortable=""true"" ");
            if (rowspan != 0)
            {
                Add(@" rowspan=""");
                Add(rowspan);
                Add(@"""");
            }
            if (colspan != 0)
            {
                Add(@" colspan=""");
                Add(colspan);
                Add(@"""");
            }
            if (!string.IsNullOrEmpty(datafield))
            {
                Add(" data-field='");
                Add(datafield);
                Add("'");
            }
            if (!string.IsNullOrEmpty(dataformatter))
            {
                Add(" data-formatter='");
                Add(dataformatter);
                Add("'");
            }
            Add(@">");
            AddEncoded(text);
            if (!string.IsNullOrEmpty(tooltip))
            {
                AddBeginTooltip(widetooltip, html);
                // important: not encoded to pass html formatting
                Add(tooltip);
                AddEndTooltip();
            }
            Add("</th>");
        }

        protected void AddCellText(string text = null, bool highlight = false, bool IsGood = false)
        {
            Add("<td class='text'>");
            if (footerMode)
                Add("<b>");
            if (highlight)
            {
                if (IsGood)
                    Add("<span class=\"ticked\">");
                else
                    Add("<span class=\"unticked\">");
            }
            AddEncoded(text);
            if (highlight)
                Add("</span>");
            if (footerMode)
                Add("</b>");
            Add(@"</td>");
        }

        protected void AddCellTextNoWrap(string text)
        {
            Add(@"<td class='text text-nowrap'>");
            if (footerMode)
                Add("<b>");
            Add(text);
            if (footerMode)
                Add("</b>");
            Add(@"</td>");
        }

        protected void AddCellDateNoWrap(DateTime text)
        {
            Add(@"<td class='text text-nowrap'>");
            if (footerMode)
                Add("<b>");
            Add(text);
            if (footerMode)
                Add("</b>");
            Add(@"</td>");
        }

        protected void AddCellNumScore(int num)
        {
            Add("<td class='num ");
            if (num == 100)
            {
                Add("score_100");
            }
            else if (num >= 75)
            {
                Add("score_over75");
            }
            else if (num >= 50)
            {
                Add("score_over50");
            }
            else if (num >= 25)
            {
                Add("score_over25");
            }
            else
            {
                Add("score_below25");
            }
            Add("'>");
            Add(num);
            Add(@"</td>");
        }

        protected void AddCellNum(int num, bool HideIfZero = false)
        {
            Add("<td class='num'>");
            if (footerMode)
                Add("<b>");
            if (!(HideIfZero && num == 0))
            {
                Add(num);
            }
            if (footerMode)
                Add("</b>");
            Add(@"</td>");
        }

        protected void AddCellDate(DateTime date)
        {
            Add("<td>");
            if (footerMode)
                Add("<b>");
            if (date == DateTime.MinValue)
                Add("Not set");
            else
                Add(date);
            if (footerMode)
                Add("</b>");
            Add(@"</td>");
        }

        protected void AddCellBool(bool? value, bool highlight = false, bool IsGood = false)
        {
            if (value != null)
            {
                AddCellText(value.Value.ToString(), highlight, IsGood);
            }
            else
            {
                AddCellText();
            }
        }

        protected enum ShowModalType
        {
            Normal,
            XL,
            FullScreen
        }

        protected void AddBeginModal(string id, string title, ShowModalType modalType = ShowModalType.Normal)
        {
            Add(@"
<!--TAB dependancy -->
<div class=""modal");
            if (modalType == ShowModalType.FullScreen)
            {
                Add(" modal-full-screen");
            }
            Add(@""" id=""");
            Add(id);
            Add(@""" tabindex=""-1"" role=""dialog"" aria-hidden=""true"">
	<div class=""modal-dialog");
            if (modalType == ShowModalType.XL)
            {
                Add(" modal-xl");
            }
            else if (modalType == ShowModalType.FullScreen)
            {
                Add(" modal-full-screen-dialog");
            }
            Add(@""" role=""dialog"">
		<div class=""modal-content");
            if (modalType == ShowModalType.FullScreen)
            {
                Add(" modal-full-screen-content");
            }
            Add(@""">
			<div class=""modal-header"">
				<h4 class=""modal-title"">");
            AddEncoded(title);
            Add(@"</h4>
					<button type=""button"" class=""btn-close"" data-bs-dismiss=""modal"" aria-label=""Close""></button>
			</div>
			<div class=""modal-body");
            if (modalType == ShowModalType.FullScreen)
            {
                Add(" modal-full-screen-body");
            }
            Add(@""">
");
        }

        protected void AddEndModal(ShowModalType modalType = ShowModalType.Normal)
        {
            Add(@"
			</div>
			<div class=""modal-footer");
            if (modalType == ShowModalType.FullScreen)
            {
                Add(" modal-full-screen-footer");
            }
            Add(@""">
				<button type=""button"" class=""btn btn-secondary"" data-bs-dismiss=""modal"">Close</button>
			</div>
		</div>
	</div>
</div>");
        }

        protected delegate void GenerateContentDelegate();

        protected abstract void GenerateFooterInformation();

        protected abstract void GenerateTitleInformation();

        protected abstract void ReferenceJSAndCSS();

        protected abstract void GenerateBodyInformation();

        protected static string favicon = @"<link href=""data:image/x-icon;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAE10lEQVRYw71XfWwTdRhet4xBssFigMja61rafbK5bGFuiqh1ISaMP2QI++jaXtvUZGKIigUkUTTzmwUxIQtRYBZHr3e9rjYOY4zLlprMEDROJagZAzEgMYiTZJvr7zrmc0cHXekXxfWSJ9f2rvc8977P+76/X0YGDsKubiSuwh2ELy8SfPVZGek+QG4hTjkhDPUrPh8grOYJwhXlCV9tSZMAdnUDBEwRZ8HsTcivE0bxJQR1QEyJ0L8+e2EFcEWlhJFfuS3gFoIQcpG4VMcRmUbcd58wqJeJ/2FYfhGwDegG9gKrUhfAly4H0UgUAWGQTyAiw8Sl3kv6qpaDcDMwDswCQaCH5fqWpCRA8D2YQ1zK/vgCQnCprgv9j9aD8FCIfA4XAGVqAj7fIBrxg6QEMIop4i7ZADI7IIQJ8AP5qaeBobYnJ0D5O6LwsIvzrADhQWAUGHJxfEOA1TwE09LEU6EUPnsk8y4rQfO0VIqxyW+IHgh4KnVWs6HaaDI/85J9t+Z4r1Pl599ZSbjiRlz/Ec8QcD4rRdRdrCOcNlcYaE6mErS1qITxGAYkeKDzam9VsdlibWptaz8DCPp2488Wq20H8daUg/TCndGS/wN8IUWXK9YSvix2k4NaCvkdi0I+DvJ9gwcbKIOR3gXiqy2t+tk5QITvoqNODZLRONELSs9mqI/wohshJl8YbJPNF+BZk4sb/BGGOw/y1lefb1WD6DDIp8LJQwK+P9bZrIQ3hpLykFTOiq/x3F1o/QW3K+GkLhPqGgir3omS9OOmoQCrXW+hjTVtesMAyIKR5CJw7fL2DlsZxDuSEyAhAAE9SIk8I9TVZHC1Fmc9zrpL7k3yPx1rCvTthkYx39GI54Drk7TZCrNp3k2uiqSUvoJSXnbr7UG6FuQjoY4mdrcXOp59biXe7nQ88hBm4A0TBJgR3pkE5KOYO83EW50zL/8gfDuiq/105NjHFPL7aRICZlGSL2NOPCblNzr5jJhSvHmtwFfI7qgAEL4ZIWDkaI8DKTAyILiRSEC7weSYYCtLQHI5Cvk0DNoDbxXic/QSBGEF8A0wDVwBbKc+sS2maVpsOJ1IxQiIpmMJgFC//9CTqATFdxGO/xu/7YG5l8VtQvCAKKKAdfdtQkutHufqNchVN1S/9i+jrurc2aI0muitIDoBwkuRUYHAM512Won7D4DwN8kLDDWGkG8F+aK7XB2pWvCAb6W8ie3XiXUCo2Dxu/7c0ZpCq9n0AEJuB+mwWAHAWXx/an/X+3l+91v3T/Loii7Vi3B5vdD/eGYKqyP1nhhGQi4VPyAyXeLQ+XBfE2WizRtNtEWsoHWAFzgNvM5xHDqdPuXl2ZbEQ0l+DSE+Cedv7uOZfJAOhBk4AFjuZX24VjJPUouTQqfXfUIFwvMRVdR1L+tDcSidS66rUcNjfNsqELrDyCdg6m2pC3CX5krDIvFQgSeobuKpXIq1YBmI3wN6ARoClqQsQPDVZUFAbwLyvzCwdmOEL537H0pYxvHeLAj4XzYq++P0c2xeVE2o7+wF3KiobaE+ENHPqUFcq8Ucly3wVk2lQ5gn5/UAp/ywaNDgKXsatmpckThY/gitiq5J+Xap8tK3WeXLb+6UGMUvWC03EV9ddkY6D2y9cpDrN9CU1kHAgub7P7CsZhuj7eUMAAAAAElFTkSuQmCC"" rel=""icon"" type=""image/x-icon"" />";
        protected static string brandLogo = @"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";

        protected void Brand(ADHealthCheckingLicense license)
        {
            if (!license.IsBasic())
            {
                try
                {
                    if (!string.IsNullOrEmpty(ConfigurationManager.AppSettings["BrandLogo"]))
                        brandLogo = ConfigurationManager.AppSettings["BrandLogo"];
                    if (!string.IsNullOrEmpty(ConfigurationManager.AppSettings["BrandCss"]))
                        AddStyle(ConfigurationManager.AppSettings["BrandCss"]);
                    if (!string.IsNullOrEmpty(ConfigurationManager.AppSettings["BrandJs"]))
                        AddScript(ConfigurationManager.AppSettings["BrandJs"]);
                }
                catch (Exception)
                {

                }
            }
        }

        protected void GenerateNavigation(string title, string domain, DateTime generationDate)
        {
            Add(@"
<nav class=""navbar py-0 navbar-expand-lg navbar-custom fixed-top border-bottom"">
	<div class=""container"">
		<a href=""#"" class=""navbar-brand"">
			<img src=""data:image/png;base64,");
            Add(brandLogo);
            Add(@""" />
		</a>
		<button class=""navbar-toggler"" type=""button"" data-bs-toggle=""collapse"" data-bs-target=""#navbarToggler"" aria-controls=""navbarToggler"" aria-expanded=""false"" aria-label=""Toggle navigation"">
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
					<a class=""nav-link p-3"" role=""button"" href=""#modalAbout"" data-bs-toggle=""modal"">About</a>
				</li>
			</ul>
		</div>
	</div>
</nav>
");
        }

        protected string GenerateUniqueID(string input, long seed)
        {
            var d = new Dictionary<char, KeyValuePair<int, int>>()
            {
                { '.', new KeyValuePair<int, int>(0x3, 3 ) },
                { 'A', new KeyValuePair<int, int>(0xF, 4 ) },
                { 'L', new KeyValuePair<int, int>(0xE, 4 ) },
                { 'O', new KeyValuePair<int, int>(0xD, 4 ) },
                { 'C', new KeyValuePair<int, int>(0xB, 4 ) },
                { 'E', new KeyValuePair<int, int>(0xA, 4 ) },
                { 'R', new KeyValuePair<int, int>(0x5, 4 ) },
                { 'S', new KeyValuePair<int, int>(0x4, 4 ) },
                { 'T', new KeyValuePair<int, int>(0x2, 4 ) },
                { 'I', new KeyValuePair<int, int>(0x1, 4 ) },
                { 'N', new KeyValuePair<int, int>(0x0, 4 ) },
                { 'M', new KeyValuePair<int, int>(0x18, 5 ) },
                { 'D', new KeyValuePair<int, int>(0x12, 5 ) },
                { 'P', new KeyValuePair<int, int>(0x7, 5 ) },
                { 'F', new KeyValuePair<int, int>(0x6, 5 ) },
                { 'G', new KeyValuePair<int, int>(0x32, 6 ) },
                { 'U', new KeyValuePair<int, int>(0x23, 6 ) },
                { '-', new KeyValuePair<int, int>(0x21, 6 ) },
                { 'B', new KeyValuePair<int, int>(0x4F, 7 ) },
                { 'Y', new KeyValuePair<int, int>(0x4C, 7 ) },
                { 'H', new KeyValuePair<int, int>(0x45, 7 ) },
                { 'Z', new KeyValuePair<int, int>(0x44, 7 ) },
                { '0', new KeyValuePair<int, int>(0xCF, 8 ) },
                { '1', new KeyValuePair<int, int>(0xCE, 8 ) },
                { 'K', new KeyValuePair<int, int>(0xCC, 8 ) },
                { 'X', new KeyValuePair<int, int>(0x9D, 8 ) },
                { 'W', new KeyValuePair<int, int>(0x9C, 8 ) },
                { 'V', new KeyValuePair<int, int>(0x9B, 8 ) },
                { '6', new KeyValuePair<int, int>(0x83, 8 ) },
                { '2', new KeyValuePair<int, int>(0x82, 8 ) },
                { '3', new KeyValuePair<int, int>(0x80, 8 ) },
                { '5', new KeyValuePair<int, int>(0x19B, 9 ) },
                { '9', new KeyValuePair<int, int>(0x19A, 9 ) },
                { '7', new KeyValuePair<int, int>(0x135, 9 ) },
                { '8', new KeyValuePair<int, int>(0x103, 9 ) },
                { '4', new KeyValuePair<int, int>(0x269, 10 ) },
                { 'Q', new KeyValuePair<int, int>(0x268, 10 ) },
                { 'J', new KeyValuePair<int, int>(0x205, 10 ) },
                { '_', new KeyValuePair<int, int>(0x204, 10 ) },
            };
            string o = null;
            foreach (char c in input.ToUpperInvariant())
            {
                if (!d.ContainsKey(c))
                    continue;
                var t = d[c];
                var v = Convert.ToString(t.Key, 2);
                if (t.Value > v.Length)
                    o += new string('0', t.Value - v.Length) + v;
                else
                    o += v.Substring(v.Length - t.Value, t.Value);
            }
            o += Convert.ToString(0x80, 2);
            byte[] bytes = new byte[o.Length / 8 + 1];
            for (int i = 0; i < bytes.Length - 1; ++i)
            {
                bytes[i] = Convert.ToByte(o.Substring(8 * i, 8), 2);
            }
            bytes[bytes.Length - 1] = (byte)(seed % 256);
            return Convert.ToBase64String(bytes).Replace("=", "");
        }

        protected void GenerateAbout()
        {
            GenerateAbout(@"<p><strong>Generated by <a href=""https://www.pingcastle.com"">Ping Castle</a> all rights reserved</strong></p>
<p>Options:</p>
<div class='form-check'>
  <input class='form-check-input' type='checkbox' value='' id='optionWideScreen'>
  <label class='form-check-label' for='optionWideScreen'>
    Enable wide mode
  </label>
</div>
<div class='form-check'>
  <input class='form-check-input' type='checkbox' value='' id='optionPagination'>
  <label class='form-check-label' for='optionPagination'>
    Remove pagination in tables
  </label>
</div>
<div class='form-check'>
  <input class='form-check-input' type='checkbox' value='' id='optionExpand'>
  <label class='form-check-label' for='optionExpand'>
    Expand all collapsed items
  </label>
</div>
<p>Open source components:</p>
<ul>
<li><a href=""https://getbootstrap.com/"">Bootstrap</a> licensed under the <a href=""https://tldrlegal.com/license/mit-license"">MIT license</a></li>
<li><a href=""https://bootstrap-table.com/"">Bootstrap Table</a> licensed under the <a href=""https://tldrlegal.com/license/mit-license"">MIT license</a></li>
<li><a href=""https://popper.js.org/"">Popper.js</a> licensed under the <a href=""https://tldrlegal.com/license/mit-license"">MIT license</a></li>
<li><a href=""https://jquery.org/"">jQuery</a> licensed under the <a href=""https://tldrlegal.com/license/mit-license"">MIT license</a></li>
</ul>");
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
                <button type=""button"" class=""btn-close"" data-bs-dismiss=""modal"" aria-label=""Close""></button>
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
                <button type=""button"" class=""btn btn-secondary"" data-bs-dismiss=""modal"">Close</button>
            </div>
        </div>

    </div>
</div>
");
        }

        protected virtual void GenerateSection(string title, GenerateContentDelegate generateContent)
        {
            Regex rgx = new Regex("[^a-zA-Z0-9-]");
            string id = "section" + rgx.Replace(title, "");
            Add(@"
<!-- Section " + title + @" -->
<div id=""" + id + @""">
	<div class=""row"">
		<div class=""col-lg-12"">
			<div class=""starter-template"">
				<div class=""card border-pc-orange mb-4 mt-4 lead fs-6"">
					<div class=""card-header h3 text-white bg-pc-orange fw-bold"">
						<a class=""sectionheader text-white""data-bs-toggle=""collapse"" aria-expanded=""true"" href=""#panel" + id + @""">" + title + @"</a>
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
<div class=""pagebreak""> </div>
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
                AddAnchor(section);
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

        protected void GenerateAccordionDetailForDetail(string id, string dataParent, string title, int itemCount, GenerateContentDelegate content, string tooltip = null)
        {
            GenerateAccordionDetail(id, dataParent, title,
                () =>
                {
                    Add(@"<i class=""float-end"">[");
                    Add((int)itemCount);
                    Add(@"]</i>");
                }, content, tooltip);
        }

        protected void GenerateAccordionDetail(string id, string dataParent, string title, GenerateContentDelegate header, GenerateContentDelegate content, string tooltip = null)
        {
            Add(@"
    <div class=""card-header"" id=""heading");
            Add(id);
            Add("\">");
            AddAnchor("anchor" + id);
            Add(@"
      <span class=""card-title mb-0"">
        <button class=""btn btn-link"" data-bs-toggle=""collapse"" data-bs-target=""#");
            Add(id);
            Add(@""" aria-expanded=""false"" aria-controls=""");
            Add(id);
            Add(@""">
          ");
            Add(title);
            if (!string.IsNullOrEmpty(tooltip))
            {
                AddBeginTooltip();
                Add(tooltip);
                AddEndTooltip();
            }
            Add(@"
        </button>
      </span>
");
            if (header != null)
            {
                header();
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

        protected static string GenerateId(string title)
        {
            return "section" + title.Replace(" ", "");
        }

        protected void GenerateTabHeader(string title, string selectedTab, bool defaultIfTabEmpty = false)
        {
            string id = GenerateId(title);
            GenerateTabHeader(title, id, selectedTab, defaultIfTabEmpty);
        }

        protected void GenerateTabHeader(string title, string id, string selectedTab, bool defaultIfTabEmpty = false)
        {
            bool isActive = (String.IsNullOrEmpty(selectedTab) ? defaultIfTabEmpty : selectedTab == id);
            Add(@"<li class=""nav-item""><a href=""#");
            Add(id);
            Add(@""" class=""nav-link ");
            if (isActive)
                Add(@"active");
            Add(@""" role=""tab"" data-bs-toggle=""tab""");
            Add(@" id=""bs-");
            Add(id);
            Add(@"""");
            Add(@">");
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
            if (TabDelegate != null)
            {
                Add(TabDelegate(title));
            }
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
                case "Windows 11":
                    return 6;
                case "Windows NT":
                    return 7;
                case "Windows 2000":
                    return 8;
                case "Windows 2003":
                    return 9;
                case "Windows 2008":
                    return 10;
                case "Windows 2012":
                    return 11;
                case "Windows 2016":
                    return 12;
                case "Windows 2019":
                    return 13;
                case "Windows 2022":
                    return 14;
                case "Windows Embedded":
                    return 15;
                case "OperatingSystem not set":
                    return 16;
            }
            return 100;
        }

        // ref: https://social.technet.microsoft.com/wiki/contents/articles/22615.how-to-get-the-number-of-computers-per-windows-operating-system-in-an-active-directory-domain-using-powershell.aspx
        // https://docs.microsoft.com/en-us/windows-server/get-started/windows-server-release-info
        // https://docs.microsoft.com/en-us/windows/release-health/release-information
        public static string GetOSVersionString(HealthcheckOSVersionData osVersion)
        {
            // ex: 10.0 (18362)
            Regex re = new Regex("(?<major>\\d+).(?<minor>\\d+)( \\((?<release>\\d+)\\))?");
            if (osVersion == null || string.IsNullOrEmpty(osVersion.OSVersion))
                return "Error";
            var m = re.Match(osVersion.OSVersion);
            if (!m.Success)
                return "Unknown (" + osVersion.OSVersion + (osVersion.IsServer ? " (Server)" : null) + ")";
            int major = int.Parse(m.Groups["major"].Value);
            int minor = int.Parse(m.Groups["minor"].Value);
            int release = 0;
            if (!string.IsNullOrEmpty(m.Groups["release"].Value))
                release = int.Parse(m.Groups["release"].Value);
            if (osVersion.IsServer)
            {
                if (major == 3)
                {
                    return "Windows NT 3.51 Server";
                }
                if (major == 4)
                {
                    return "Windows NT 4.0 Server";
                }
                if (major == 5)
                {
                    if (minor == 0)
                    {
                        return "Windows 2000 Server";
                    }
                    if (minor == 1)
                    {
                        return "Windows Server 2003";
                    }
                    if (minor == 2)
                    {
                        return "Windows Server 2003 SP2";
                    }
                }
                if (major == 6)
                {
                    if (minor == 0)
                        return "Windows Server 2008";
                    if (minor == 1)
                        return "Windows Server 2008 R2";
                    if (minor == 2)
                        return "Windows Server 2012";
                    if (minor == 3)
                        return "Windows Server 2012 R2";
                }
                if (major == 10)
                {
                    if (minor == 0)
                    {
                        switch (release)
                        {
                            case 14393: return "Windows Server 2016 1607";
                            //case 16299:
                            case 17763: return "Windows Server 2019 1809";
                            case 18362: return "Windows Server 2019 1903";
                            case 18363: return "Windows Server 2019 1909";
                            case 19041: return "Windows Server 2019 2004";
                            case 19042: return "Windows Server 2019 20H2";
                            // https://learn.microsoft.com/en-us/windows-server/get-started/windows-server-release-info
                            case 20348: return "Windows Server 2022 21H2";
                            case 25398: return "Windows Server 2022 23H2";
                            case 26100: return "Windows Server 2025 24H2";
                            default: return "Windows Server (Build " + release + ")";
                        }
                    }
                }
            }
            else
            {
                if (major == 3)
                {
                    return "Windows NT 3.51 Workstation";
                }
                if (major == 4)
                {
                    return "Windows NT 4.0 Workstation";
                }
                if (major == 5)
                {
                    if (minor == 0)
                        return "Windows 2000";
                    if (minor == 1)
                        return "Windows XP";
                    if (minor == 2)
                        return "Windows XP 64-Bit Edition";
                }
                if (major == 6)
                {
                    if (minor == 0)
                        return "Windows Vista";
                    if (minor == 1)
                        return "Windows 7";
                    if (minor == 2)
                        return "Windows 8";
                    if (minor == 3)
                        return "Windows 8.1";
                }
                if (major == 10 && minor == 0)
                {
                    string w;
                    switch (release)
                    {
                        case 26100: w = "Windows 11 24H2"; break;
                        case 22631: w = "Windows 11 23H2"; break;
                        case 22621: w = "Windows 11 22H2"; break;
                        case 22000: w = "Windows 11 21H2"; break;
                        case 22449:
                        case 22518:
                        case 21996: w = "Windows 11 Dev (" + release + ")"; break;
                        case 20185: w = "Windows 10 21H1 Dev"; break;
                        case 19045: w = "Windows 10 22H2"; break;
                        case 19044: w = "Windows 10 21H2"; break;
                        case 19043: w = "Windows 10 21H1"; break;
                        case 19042: w = "Windows 10 20H2"; break;
                        case 18908: w = "Windows 10 20H1"; break;
                        case 18356: w = "Windows 10 19H1"; break;
                        case 19041: w = "Windows 10 2004"; break;
                        case 18363: w = "Windows 10 1909"; break;
                        case 18362: w = "Windows 10 1903"; break;
                        case 17763: w = "Windows 10 1809"; break;
                        case 17134: w = "Windows 10 1803"; break;
                        case 16299: w = "Windows 10 1709"; break;
                        case 15063: w = "Windows 10 1703"; break;
                        case 14393: w = "Windows 10 1607"; break;
                        case 10586: w = "Windows 10 1511"; break;
                        case 10240: w = "Windows 10 1507"; break;
                        default:
                            if (release >= 22000)
                            {
                                w = "Windows 11 (Build " + release + ")"; break;
                            }
                            else
                            {
                                w = "Windows 10 (Build " + release + ")"; break;
                            }
                    }
                    return w + (osVersion.IsIOT ? " IOT" : null) + (osVersion.IsLTSC ? " (LTSC)" : null);
                }
            }
            return "Unknown (" + osVersion.OSVersion + (osVersion.IsServer ? " (Server)" : null) + ")";
        }

        protected void AddPSOStringValue(GPPSecurityPolicy policy, string propertyName)
        {
            foreach (var property in policy.Properties)
            {
                if (property.Property == propertyName)
                {
                    if (property.Value == 0)
                    {
                        if (propertyName == "PasswordComplexity")
                        {
                            Add("<td><span class=\"unticked\">False</span></td>");
                            return;
                        }
                        if (propertyName == "ClearTextPassword"
                            || propertyName == "ScreenSaveActive" || propertyName == "ScreenSaverIsSecure")
                        {
                            AddCellText("False");
                            return;
                        }
                    }
                    if (property.Value == -1 && propertyName == "MaximumPasswordAge")
                    {
                        Add("<td><span class=\"unticked\">Never expires</span></td>");
                        return;
                    }
                    if (property.Value == 1)
                    {
                        if (propertyName == "ClearTextPassword")
                        {
                            Add("<td><span class=\"unticked\">True</span></td>");
                            return;
                        }
                        if (propertyName == "PasswordComplexity"
                            || propertyName == "ScreenSaveActive" || propertyName == "ScreenSaverIsSecure")
                        {
                            AddCellText("True");
                            return;
                        }
                    }
                    if (propertyName == "MinimumPasswordLength")
                    {
                        if (property.Value < 8)
                        {
                            Add("<td><span class=\"unticked\">" + property.Value.ToString() + "</span></td>");
                            return;
                        }
                    }
                    if (propertyName == "MinimumPasswordAge")
                    {
                        if (property.Value == 0)
                        {
                            Add("<td><span class=\"unticked\">0 day</span></td>");
                            return;
                        }
                        AddCellText(property.Value + " day(s)");
                        return;
                    }
                    if (propertyName == "MaximumPasswordAge")
                    {
                        AddCellText(property.Value + " day(s)");
                        return;
                    }
                    if (propertyName == "ResetLockoutCount" || propertyName == "LockoutDuration")
                    {
                        if (property.Value <= 0)
                        {
                            AddCellText("Infinite");
                            return;
                        }
                        AddCellText(property.Value + " minute(s)");
                        return;
                    }
                    AddCellNum(property.Value);
                    return;
                }
            }
            AddCellText("Not Set");
        }

        protected string GetLinkForLsaSetting(string property)
        {
            switch (property.ToLowerInvariant())
            {
                case "enableguestaccount":
                    return @"<a href=""https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/accounts-guest-account-status"">Guest account</a> (<a href=""https://msdn.microsoft.com/en-us/library/hh128296.aspx"">Technical details</a>)";
                case "lsaanonymousnamelookup":
                    return @"<a href=""https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-allow-anonymous-sidname-translation"">Allow anonymous SID/Name translation</a> (<a href=""https://msdn.microsoft.com/en-us/library/hh128296.aspx"">Technical details</a>)";
                case "everyoneincludesanonymous":
                    return @"<a href=""https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-let-everyone-permissions-apply-to-anonymous-users"">Let Everyone permissions apply to anonymous users</a>";
                case "limitblankpassworduse":
                    return @"<a href=""https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/accounts-limit-local-account-use-of-blank-passwords-to-console-logon-only"">Limit local account use of blank passwords to console logon only</a> (<a href=""https://technet.microsoft.com/en-us/library/jj852174.aspx"">Technical details</a>)";
                case "forceguest":
                    return @"<a href=""https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-sharing-and-security-model-for-local-accounts"">Sharing and security model for local accounts</a> (<a href=""https://technet.microsoft.com/en-us/library/jj852219%28v=ws.11%29.aspx"">Technical details</a>)";
                case "lmcompatibilitylevel":
                    return @"<a href=""https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level"">LAN Manager authentication level</a> (<a href=""https://technet.microsoft.com/en-us/library/cc960646.aspx"">Technical details</a>)";
                case "nolmhash":
                    return @"<a href=""https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-do-not-store-lan-manager-hash-value-on-next-password-change"">Do not store LAN Manager hash value on next password change</a> (<a href=""https://technet.microsoft.com/en-us/library/cc736342%28v=ws.10%29.aspx"">Technical details</a>)";
                case "restrictanonymous":
                    return @"<a href=""https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-do-not-allow-anonymous-enumeration-of-sam-accounts-and-shares"">Do not allow anonymous enumeration of SAM accounts and shares</a> (<a href=""https://technet.microsoft.com/en-us/library/cc963223.aspx"">Technical details</a>)";
                case "restrictanonymoussam":
                    return @"<a href=""https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-do-not-allow-anonymous-enumeration-of-sam-accounts"">Do not allow anonymous enumeration of SAM accounts</a> (<a href=""https://technet.microsoft.com/en-us/library/jj852184.aspx"">Technical details</a>)";
                case "ldapclientintegrity":
                    return @"<a href=""https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-ldap-client-signing-requirements"">LDAP client signing requirements</a> (<a href=""https://support.microsoft.com/en-us/help/935834/how-to-enable-ldap-signing-in-windows-server-2008"">Technical details</a>)";
                case "recoveryconsole_securitylevel":
                    return @"<a href=""https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/recovery-console-allow-automatic-administrative-logon"">Recovery console: Allow automatic administrative logon</a>";
                case "refusepasswordchange":
                    return @"<a href=""https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/domain-controller-refuse-machine-account-password-changes"">Refuse machine account password changes</a> (<a href=""https://support.microsoft.com/en-us/help/154501/how-to-disable-automatic-machine-account-password-changes"">Technical details</a>)";
                case "enablemulticast":
                    return @"<a href=""https://docs.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-dnsclient#admx-dnsclient-turn-off-multicast"">Turn off multicast name resolution</a> (<a href=""https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-llmnrp/02b1d227-d7a2-4026-9fd6-27ea5651fe85"">Technical details</a>)";
                case "enablesecuritysignature":
                    return @"<a href=""https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/smbv1-microsoft-network-server-digitally-sign-communications-if-client-agrees"">Microsoft network server: Digitally sign communications (if client agrees)</a> (<a href=""https://www.stigviewer.com/stig/windows_server_2016/2017-11-20/finding/V-73663"">Technical details</a>)";
                case "enablemodulelogging":
                    return @"<a href=""https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings?view=powershell-6"">Powershell: Turn on Module logging</a>";
                case "enablescriptblocklogging":
                    return @"<a href=""https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings?view=powershell-6"">Powershell: Turn on Powershell Script Block logging</a>";
                case "srvsvcsessioninfo":
                    return @"<a href=""https://github.com/p0w3rsh3ll/NetCease"">Hardening Net Session Enumeration</a>";
                case "supportedencryptiontypes":
                    return @"<a href=""https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos"">Network security: Configure encryption types allowed for Kerberos</a>";
                case "enablecbacandarmor":
                    return @"<a href=""https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-kerberos"">Kerberos client support for claims, compound authentication and Kerberos armoring</a>";
                case "cbacandarmorlevel":
                    return @"<a href=""https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/operations/ad-fs-compound-authentication-and-ad-ds-claims"">KDC support for claims compound authentication and Kerberos armoring</a>";
                case "msv1_0\\restrictsendingntlmtraffic":
                    return @"<a href=""https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-outgoing-ntlm-traffic-to-remote-servers"">Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers</a>";
                default:
                    return property;
            }
        }

        protected void AddLsaSettingsValue(string property, int value)
        {
            Add("<td class='text'>");
            switch (property.ToLowerInvariant())
            {
                case "enablemulticast":
                    if (value == 0)
                    {
                        Add(@"<span class=""ticked"">LLMNR disabled</span>");
                    }
                    else
                    {
                        Add(@"<span class=""unticked"">LLMNR Enabled</span>");
                    }
                    break;
                case "lmcompatibilitylevel":
                    if (value == 0)
                    {
                        Add(@"<span class=""unticked"">Send LM & NTLM responses</span>");
                    }
                    else if (value == 1)
                    {
                        Add(@"<span class=""unticked"">Send LM & NTLM</span>");
                    }
                    else if (value == 2)
                    {
                        Add(@"<span class=""unticked"">Send NTLM response only</span>");
                    }
                    else if (value == 3)
                    {
                        Add("Send NTLMv2 response only");
                    }
                    else if (value == 4)
                    {
                        Add("Send NTLMv2 response only. Refuse LM Client devices");
                    }
                    else if (value == 5)
                    {
                        Add("Send NTLMv2 response only. Refuse LM & NTLM");
                    }
                    break;
                case "ldapclientintegrity":
                    if (value == 0)
                    {
                        Add(@"<span class=""unticked"">None</span> (Do not request signature)");
                    }
                    else
                    {
                        Add(value);
                    }
                    break;
                case "srvsvcsessioninfo":
                case "enablemodulelogging":
                case "enablescriptblocklogging":
                case "enablecbacandarmor":
                case "cbacandarmorlevel":
                    if (value == 0)
                    {
                        Add(@"<span class=""unticked"">Disabled</span>");
                    }
                    else
                    {
                        Add(@"<span class=""ticked"">Enabled</span>");
                    }
                    break;
                case "msv1_0\\restrictsendingntlmtraffic":
                    if (value == 0)
                    {
                        Add(@"<span class=""unticked"">Allow All</span>");
                    }
                    else if (value == 1)
                    {
                        Add(@"<span class=""unticked"">Audit</span> (Deny All is not enabled)");
                    }
                    else if (value == 2)
                    {
                        Add(@"<span class=""ticked"">Deny All</span>");
                    }
                    break;
                case "supportedencryptiontypes":
                    Add(SupportedEncryptionTypeToString(value));
                    break;
                default:
                    if (value == 0)
                    {
                        Add(@"<span class=""unticked"">Disabled</span>");
                    }
                    else
                    {
                        Add(@"<span class=""unticked"">Enabled</span>");
                    }
                    break;
            }
            Add("</td>");
        }

        protected string SupportedEncryptionTypeToString(int msDSSupportedEncryptionTypes)
        {
            // see https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/6cfc7b50-11ed-4b4d-846d-6f08f0812919
            List<string> algs = new List<string>();
            if ((msDSSupportedEncryptionTypes & 1) != 0)
            {
                algs.Add(@"<span class=""unticked"">DES-CBC-CRC</span>");
            }
            if ((msDSSupportedEncryptionTypes & 2) != 0)
            {
                algs.Add(@"<span class=""unticked"">DES-CBC-MD5</span>");
            }
            if ((msDSSupportedEncryptionTypes & 4) != 0)
            {
                algs.Add("RC4-HMAC");
            }
            if ((msDSSupportedEncryptionTypes & 8) != 0)
            {
                algs.Add(@"<span class=""ticked"">AES128-CTS-HMAC-SHA1-96</span>");
            }
            if ((msDSSupportedEncryptionTypes & 16) != 0)
            {
                algs.Add(@"<span class=""ticked"">AES256-CTS-HMAC-SHA1-96</span>");
            }
            if ((msDSSupportedEncryptionTypes & ~(1 + 2 + 4 + 8 + 16)) != 0)
            {
                algs.Add(@"Future encryption");
            }
            return string.Join(", ", algs.ToArray());
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

        protected string PrintDomain(DomainKey key, string risk)
        {
            string label = key.DomainName;
            if (String.IsNullOrEmpty(label))
            {
                if (!String.IsNullOrEmpty(key.DomainNetBIOS))
                    label = key.DomainNetBIOS;
                else
                    label = key.DomainSID;
            }
            if (GetUrlCallbackDomain == null)
                return label;
            string htmlData = GetUrlCallbackDomain(key, label, risk);
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

        void AddPath(double radius, double startAngle, double endAngle, string idx, string tooltip = null, string fill = null)
        {

            var isCircle = (endAngle - startAngle) == 360;

            if (isCircle)
            {
                endAngle--;
            }
            var start = polarToCartesian(radius, startAngle);
            var end = polarToCartesian(radius, endAngle);
            var largeArcFlag = endAngle - startAngle <= 180 ? 0 : 1;
            var d = new List<string> {
                "M", start.Item1.ToString(), start.Item2.ToString(),
                "A", radius.ToString(), radius.ToString(), 0.ToString(), largeArcFlag.ToString(), 1.ToString(), end.Item1.ToString(), end.Item2.ToString()
                };

            if (isCircle)
            {
                d.Add("Z");
            }
            else
            {
                d.AddRange(new string[]{"L", radius.ToString(), radius.ToString(),
                    "L", start.Item1.ToString(), start.Item2.ToString(),
                    "Z" });
            }
            Add("<path d=\"");
            Add(string.Join(" ", d.ToArray()));
            Add("\" ");
            if (!string.IsNullOrEmpty(idx))
            {
                Add(" class=\"");
                Add(idx);
                Add("\"");
            }
            if (!string.IsNullOrEmpty(fill))
            {
                Add(" fill=\"");
                Add(fill);
                Add("\"");
            }
            if (!string.IsNullOrEmpty(tooltip))
            {
                Add(" data-bs-toggle=\"tooltip\" title=\"");
                AddEncoded(tooltip);
                Add("\"");
            }
            Add("/>");
        }
        Tuple<int, int> polarToCartesian(double radius, double angleInDegrees)
        {
            var radians = (angleInDegrees - 90) * Math.PI / 180;
            return new Tuple<int, int>((int)Math.Round(radius + (radius * Math.Cos(radians))),
                    (int)Math.Round(radius + (radius * Math.Sin(radians))));
        }

        protected void AddPie(int radius, int total, params int[] vals)
        {
            AddPie(radius, total, vals.ToList(), null);
        }

        protected void AddPie(int radius, int total, List<int> vals, List<string> tooltips)
        {
            var width = radius * 2;
            Add("<svg xmlns:xlink=\"http://www.w3.org/1999/xlink\" viewBox = \"0 0 ");
            Add(width);
            Add(" ");
            Add(width + "\" ><g class='sectors'>");

            if (total == 0)
                total = vals.Sum();

            int i = 0;
            int previousto = 0;
            int t = 0;
            for (int index = 0; index < vals.Count; index++)
            {
                var val = vals[index];
                var degrees = (int)(((double)val / total) * 360);
                int from = previousto;
                int to = degrees + from;
                previousto = to;

                string tooltip = null;
                if (tooltips != null && index < tooltips.Count + 1)
                {
                    tooltip = tooltips[i];
                }

                AddPath(radius, from, to, null, tooltip: tooltip, fill: GetColor(index, vals.Count));
                t += val;
            }
            if (t != total)
                AddPath(radius, previousto, previousto + ((double)(total - t) / total) * 360, "empty");

            Add("</g></svg>");
        }

        protected class DistributionItem
        {
            public int HigherBound { get; set; }
            public int Value { get; set; }
            public string toolTip { get; set; }
        }


        protected void AddDistributionChart(IEnumerable<DistributionItem> input, string id)
        {
            AddDistributionSeriesChart(new Dictionary<string, IEnumerable<DistributionItem>> { { string.Empty, input } }, id);
        }

        protected void AddDistributionSeriesChart(IDictionary<string, IEnumerable<DistributionItem>> input, string id)
        {
            const int division = 36;
            const double horizontalStep = 25;
            NumberFormatInfo nfi = new NumberFormatInfo();
            nfi.NumberDecimalSeparator = ".";

            bool single = input.Count == 1;

            int highest = 0;
            var global = new SortedDictionary<string, SortedDictionary<int, DistributionItem>>();
            foreach (var inputDetail in input)
            {
                if (inputDetail.Value == null)
                    continue;
                var data = new SortedDictionary<int, DistributionItem>();
                global[inputDetail.Key] = data;

                // determine max X
                foreach (var entry in inputDetail.Value)
                {
                    data.Add(entry.HigherBound, entry);
                    if (highest < entry.HigherBound)
                        highest = entry.HigherBound;
                }

                // add missing data
                for (int i = 0; i < division; i++)
                {
                    if (!data.ContainsKey(i))
                        data[i] = new DistributionItem { HigherBound = i, Value = 0 };
                }
            }
            // determine max Y

            int max = 0;
            for (int i = 0; i < division; i++)
            {
                int value = global.Select(x => x.Value[i].Value).Max();
                if (value > max)
                    max = value;
            }

            // adjust max Y
            if (max > 10000)
                max = 10000;
            else if (max >= 5000)
                max = 10000;
            else if (max >= 1000)
                max = 5000;
            else if (max >= 500)
                max = 1000;
            else if (max >= 100)
                max = 500;
            else if (max >= 50)
                max = 100;
            else if (max >= 10)
                max = 50;
            else
                max = 10;


            // draw chart
            Add(@"<div id='pdwdistchart");
            Add(id);
            Add(@"'><svg viewBox='0 0 1000 400'>");
            Add(@"<g transform=""translate(40,20)"">");
            // horizontal scale
            Add(@"<g transform=""translate(0,290)"" fill=""none"" font-size=""10"" font-family=""sans-serif"" text-anchor=""middle"">");
            Add(@"<path class=""domain"" stroke=""#000"" d=""M0.5,0V0.5H950V0""></path>");
            for (int i = 0; i < division; i++)
            {
                double v = 13.06 + (i) * horizontalStep;
                Add(@"<g class=""tick"" opacity=""1"" transform=""translate(" + v.ToString(nfi) + @",30)""><line stroke=""#000"" y2=""0""></line><text fill=""#000"" y=""3"" dy="".15em"" dx=""-.8em"" transform=""rotate(-65)"">" +
                    (i * 30) + "-" + ((i + 1) * 30) + @" days</text></g>");
            }
            {
                double v = 13.06 + (division) * horizontalStep;
                Add(@"<g class=""tick"" opacity=""1"" transform=""translate(" + v.ToString(nfi) + @",30)""><line stroke=""#000"" y2=""0""></line><text fill=""#000"" y=""3"" dy="".15em"" dx=""-.8em"" transform=""rotate(-65)"">Other</text></g>");
            }
            Add(@"</g>");
            // vertical scale
            Add(@"<g fill=""none"" font-size=""10"" font-family=""sans-serif"" text-anchor=""end"">");
            Add(@"<path class=""domain"" stroke=""#000"" d=""M-6,290.5H0.5V0.5H-6""></path>");
            for (int i = 0; i < 6; i++)
            {
                double v = 290 - i * 55;
                Add(@"<g class=""tick"" opacity=""1"" transform=""translate(0," + v.ToString(nfi) + @")""><line stroke=""#000"" x2=""-6""></line><text fill=""#000"" x=""-9"" dy=""0.32em"">" +
                    (max / 5 * i) + @"</text></g>");
            }
            Add(@"</g>");
            // bars
            double cumulatedSize = 0;

            for (int i = 0; i < division; i++)
            {
                cumulatedSize = 0;
                int serieindex = 0;
                foreach (var serie in global.Keys)
                {
                    double v = 3.28 + horizontalStep * (i);
                    int value = 0;
                    if (global[serie].ContainsKey(i))
                        value = global[serie][i].Value;
                    double size = 290 * value / max;
                    if (size > 290) size = 290;

                    double w = horizontalStep - 3;
                    string tooltip = value.ToString();
                    if (!string.IsNullOrEmpty(global[serie][i].toolTip))
                        tooltip = global[serie][i].toolTip;
                    if (!single)
                        tooltip = serie + ": " + tooltip;
                    Add(@"<rect class=""bar"" fill=""");
                    Add(GetColor(serieindex++, global.Count));
                    Add(@""" x=""" + v.ToString(nfi) + @""" width=""" + w.ToString(nfi) + @""" y=""" + (290 - size - cumulatedSize).ToString(nfi) + @""" height=""" + (size).ToString(nfi) + @""" data-bs-toggle=""tooltip"" title=""");
                    AddEncoded(tooltip);
                    Add(@"""></rect>");
                    cumulatedSize += size;
                }
            }
            // last item (because max X may be restricted, as missing data here)
            cumulatedSize = 0;
            var otherValues = new Dictionary<string, int>();
            foreach (var serie in global.Keys)
            {
                int other = 0;

                for (int i = division; i <= highest; i++)
                {
                    if (global[serie].ContainsKey(i))
                        other += global[serie][i].Value;
                }
                otherValues[serie] = other;
                cumulatedSize += other;
            }

            double ratio = 1;
            if (cumulatedSize > max)
            {
                ratio = cumulatedSize / max;
            }

            cumulatedSize = 0;
            int i1 = 0;
            foreach (var serie in global.Keys)
            {
                double v = 3.28 + horizontalStep * (division);
                int value = otherValues[serie];
                double size = 290 * value / max / ratio;
                if (size > 290) size = 290;
                double w = horizontalStep - 3;
                string tooltip = string.Empty;

                foreach (var t in global[serie].Keys)
                {
                    if (t > division && !string.IsNullOrEmpty(global[serie][t].toolTip))
                        tooltip += global[serie][t].toolTip + "\r\n";
                }

                if (string.IsNullOrEmpty(tooltip))
                    tooltip += value.ToString();

                if (!single)
                    tooltip = serie + ": " + tooltip;


                Add(@"<rect class=""bar"" fill=""");
                Add(GetColor(i1++, global.Count));
                Add(@""" x=""" + v.ToString(nfi) + @""" width=""" + w.ToString(nfi) + @""" y=""" + (290 - cumulatedSize - size).ToString(nfi) + @""" height=""" + (size).ToString(nfi) + @""" data-bs-toggle=""tooltip"" title=""");
                AddEncoded(tooltip);
                Add(@"""></rect>");
                cumulatedSize += size;
            }
            Add(@"</g></svg></div>");
        }

        static string[] colors = new string[] { 
                                "#ff0029",
                                "#377eb8",
                                "#66a61e",
                                "#984ea3",
                                "#00d2d5",
                                "#ff7f00",
                                "#af8d00",
                                "#7f80cd",
                                "#b3e900",
                                "#c42e60",
                                "#a65628",
                                "#f781bf",
                                "#8dd3c7",
                                "#bebada",
                                "#fb8072",
                                "#80b1d3",
                                "#fdb462",
                                "#fccde5",
                                "#bc80bd",
                                "#ffed6f",
        };

        string GetColor(int index, int NumberOfKeys)
        {
            if (NumberOfKeys == 1)
                return "#Fa9C1A";
            return colors[index % colors.Length];
        }
    }
}
