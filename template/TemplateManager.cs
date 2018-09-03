//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Text;

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
                gzip = new GZipStream(stream, CompressionMode.Decompress);
                reader = new StreamReader(gzip);
                html = reader.ReadToEnd();
            }
            finally
            {
                if (reader  != null)
                    reader.Dispose();
            }
            return html;
        }


        public static string LoadResponsiveTemplate()
        {
			return LoadTemplate(typeof(TemplateManager).Namespace + ".responsivetemplate.html.gz"); 
        }

		public static string LoadVisJs()
		{
			return LoadTemplate(typeof(TemplateManager).Namespace + ".vis.min.js.gz");
		}

		public static string LoadVisCss()
		{
			return LoadTemplate(typeof(TemplateManager).Namespace + ".vis.min.css.gz");
		}
	}
}
