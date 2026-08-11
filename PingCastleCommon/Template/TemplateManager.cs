using System;
using System.Diagnostics;
//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System.IO;
using System.IO.Compression;
using System.Reflection;

namespace PingCastle.template
{
    public class TemplateManager
    {

        private static string LoadTemplate(string resourceName)
        {
            var assembly = Assembly.GetExecutingAssembly();
            Stream stream = null;
            GZipStream gzip = null;
            string html = null;
            StreamReader reader = null;
            try
            {
                stream = assembly.GetManifestResourceStream(resourceName);
                if (stream == null)
                {
                    Trace.WriteLine($"Resource not found: {resourceName}");
                    Trace.WriteLine("Available resources:");
                    foreach (var name in assembly.GetManifestResourceNames())
                    {
                            Trace.WriteLine("  " + name);
                    }
                }

                gzip = new GZipStream(stream, CompressionMode.Decompress);
                reader = new StreamReader(gzip);
                html = reader.ReadToEnd();
            }
            catch(Exception)
            {
                Trace.WriteLine("Unable to load " + resourceName);
                throw;
            }
            finally
            {
                if (reader != null)
                    reader.Dispose();
            }
            return html;
        }

        private const string ResourceNamespace = "PingCastleCommon.Template";

        public static string LoadResponsiveTemplate()
        {
            return LoadTemplate(ResourceNamespace + ".responsivetemplate.html.gz");
        }

        public static string LoadBootstrapCss()
        {
            return LoadTemplate(ResourceNamespace + ".bootstrap.min.css.gz");
        }

        public static string LoadBootstrapJs()
        {
            return LoadTemplate(ResourceNamespace + ".bootstrap.min.js.gz");
        }

        public static string LoadBootstrapTableCss()
        {
            return LoadTemplate(ResourceNamespace + ".bootstrap-table.min.css.gz");
        }

        public static string LoadBootstrapTableJs()
        {
            return LoadTemplate(ResourceNamespace + ".bootstrap-table.min.js.gz");
        }

        public static string LoadBootstrapTableExportJs()
        {
            return LoadTemplate(ResourceNamespace + ".bootstrap-table-export.min.js.gz");
        }

        public static string LoadTableExportJs()
        {
            return LoadTemplate(ResourceNamespace + ".tableExport.min.js.gz");
        }

        public static string LoadPopperJs()
        {
            return LoadTemplate(ResourceNamespace + ".popper.min.js.gz");
        }

        public static string LoadJqueryJs()
        {
            return LoadTemplate(ResourceNamespace + ".jquery.min.js.gz");
        }

        public static string LoadMarkedJs()
        {
            return LoadTemplate(ResourceNamespace + ".marked.min.js.gz");
        }

        public static string LoadPurifyJs()
        {
            return LoadTemplate(ResourceNamespace + ".purify.min.js.gz");
        }

        public static string LoadVisJs()
        {
            return LoadTemplate(ResourceNamespace + ".vis.min.js.gz");
        }

        public static string LoadVisCss()
        {
            return LoadTemplate(ResourceNamespace + ".vis.min.css.gz");
        }

        public static string LoadReportBaseCss()
        {
            return LoadTemplate(ResourceNamespace + ".ReportBase.css.gz");
        }

        public static string LoadReportFontsCss()
        {
            return LoadTemplate(ResourceNamespace + ".ReportFonts.css.gz");
        }

        public static string LoadFontAwesomeCss()
        {
            return LoadTemplate(ResourceNamespace + ".fontawesome.all.min.css.gz");
        }

        public static string LoadReportBaseJs()
        {
            return LoadTemplate(ResourceNamespace + ".ReportBase.js.gz");
        }

        public static string LoadReportCloudMainJs()
        {
            return LoadTemplate(ResourceNamespace + ".ReportCloudMain.js.gz");
        }

        public static string LoadReportRiskControlsCss()
        {
            return LoadTemplate(ResourceNamespace + ".ReportRiskControls.css.gz");
        }

        public static string LoadReportHealthCheckConsolidationCss()
        {
            return LoadTemplate(ResourceNamespace + ".ReportHealthCheckConsolidation.css.gz");
        }

        public static string LoadReportHealthCheckRulesCss()
        {
            return LoadTemplate(ResourceNamespace + ".ReportHealthCheckRules.css.gz");
        }

        public static string LoadReportCompromiseGraphCss()
        {
            return LoadTemplate(ResourceNamespace + ".ReportCompromiseGraph.css.gz");
        }

        public static string LoadReportCompromiseGraphJs()
        {
            return LoadTemplate(ResourceNamespace + ".ReportCompromiseGraph.js.gz");
        }

        public static string LoadReportMapBuilderCss()
        {
            return LoadTemplate(ResourceNamespace + ".ReportMapBuilder.css.gz");
        }

        public static string LoadReportMapBuilderJs()
        {
            return LoadTemplate(ResourceNamespace + ".ReportMapBuilder.js.gz");
        }

        public static string LoadReportNetworkMapCss()
        {
            return LoadTemplate(ResourceNamespace + ".ReportNetworkMap.css.gz");
        }

        public static string LoadReportNetworkMapJs()
        {
            return LoadTemplate(ResourceNamespace + ".ReportNetworkMap.js.gz");
        }
    }
}
